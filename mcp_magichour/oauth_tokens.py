"""Sealed (encrypted) OAuth access and refresh tokens.

When ``MCP_OAUTH_TOKEN_SECRET`` is configured the OAuth compatibility server
stops handing the user's raw Magic Hour credential to OAuth clients. Instead it
issues opaque tokens that only this server can open:

* an **access token** carrying the credential, the audience (``resource``) the
  token was minted for, the OAuth client, the granted scope and an expiry;
* a **refresh token** (rotating) that lets the client obtain a new access token
  without asking the user to authorize again.

Tokens are AES-256-GCM sealed and self-contained, so any server instance can
verify them without shared state - which is what a serverless deployment such
as Vercel needs. Nothing about the payload is recoverable without the secret.

The format is ``mhmcp_v1.<base64url(nonce || ciphertext || tag)>``. Legacy
clients that authenticate with a raw Magic Hour API key keep working because
``openapi_auth`` only unwraps tokens that carry the ``mhmcp_v1.`` prefix.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
from dataclasses import dataclass
from time import time
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


TOKEN_PREFIX = "mhmcp_v1."
_AAD = b"magic-hour-mcp/oauth/v1"
_NONCE_BYTES = 12
MIN_SECRET_LENGTH = 32
DEFAULT_ACCESS_TOKEN_TTL = 8 * 60 * 60
DEFAULT_REFRESH_TOKEN_TTL = 30 * 24 * 60 * 60
MAX_TOKEN_LENGTH = 4096


class TokenError(Exception):
    """A sealed token could not be opened or failed validation."""


@dataclass(frozen=True)
class TokenClaims:
    kind: str
    credential: str
    client_id: str
    resource: str | None
    scope: str
    issued_at: int
    expires_at: int

    @property
    def expires_in(self) -> int:
        return max(0, self.expires_at - int(time()))


@dataclass(frozen=True)
class IssuedTokens:
    access_token: str
    refresh_token: str
    expires_in: int
    scope: str


class SealedTokenCodec:
    """Encrypt and decrypt self-contained OAuth tokens with one server secret."""

    def __init__(
        self,
        secret: str,
        *,
        access_ttl_seconds: int = DEFAULT_ACCESS_TOKEN_TTL,
        refresh_ttl_seconds: int = DEFAULT_REFRESH_TOKEN_TTL,
    ) -> None:
        if not isinstance(secret, str) or len(secret) < MIN_SECRET_LENGTH:
            raise RuntimeError(
                f"MCP_OAUTH_TOKEN_SECRET must be at least {MIN_SECRET_LENGTH} characters"
            )
        if access_ttl_seconds <= 0 or refresh_ttl_seconds <= 0:
            raise RuntimeError("OAuth token lifetimes must be positive")
        # Stretch an operator-chosen passphrase into a fixed-size AES key. The
        # secret is never stored; only the derived key lives in memory.
        self._aead = AESGCM(hashlib.sha256(secret.encode("utf-8")).digest())
        self.access_ttl_seconds = access_ttl_seconds
        self.refresh_ttl_seconds = refresh_ttl_seconds

    @classmethod
    def from_env(cls) -> "SealedTokenCodec | None":
        secret = os.getenv("MCP_OAUTH_TOKEN_SECRET", "").strip()
        if not secret:
            return None
        return cls(
            secret,
            access_ttl_seconds=_positive_int_env("MCP_OAUTH_ACCESS_TOKEN_TTL", DEFAULT_ACCESS_TOKEN_TTL),
            refresh_ttl_seconds=_positive_int_env("MCP_OAUTH_REFRESH_TOKEN_TTL", DEFAULT_REFRESH_TOKEN_TTL),
        )

    # -- issuing -----------------------------------------------------------

    def issue(
        self,
        *,
        credential: str,
        client_id: str,
        resource: str | None,
        scope: str = "",
    ) -> IssuedTokens:
        now = int(time())
        access = self._seal(
            {
                "t": "access",
                "k": credential,
                "cid": client_id,
                "aud": resource,
                "scope": scope,
                "iat": now,
                "exp": now + self.access_ttl_seconds,
            }
        )
        refresh = self._seal(
            {
                "t": "refresh",
                "k": credential,
                "cid": client_id,
                "aud": resource,
                "scope": scope,
                "iat": now,
                "exp": now + self.refresh_ttl_seconds,
                # Random salt so rotated refresh tokens are never byte-identical.
                "jti": secrets.token_urlsafe(9),
            }
        )
        return IssuedTokens(
            access_token=access,
            refresh_token=refresh,
            expires_in=self.access_ttl_seconds,
            scope=scope,
        )

    # -- verifying ---------------------------------------------------------

    def open_access_token(self, token: str) -> TokenClaims:
        claims = self._open(token)
        if claims.kind != "access":
            raise TokenError("Not an access token")
        return claims

    def open_refresh_token(self, token: str) -> TokenClaims:
        claims = self._open(token)
        if claims.kind != "refresh":
            raise TokenError("Not a refresh token")
        return claims

    @staticmethod
    def is_sealed(token: str) -> bool:
        return token.startswith(TOKEN_PREFIX)

    # -- generic sealed payloads (e.g. pending login state) ----------------

    def seal_payload(self, kind: str, payload: dict[str, Any], *, ttl_seconds: int) -> str:
        """Seal an arbitrary short-lived payload under a distinct ``kind``."""
        if kind in {"access", "refresh"}:
            raise ValueError("Use issue() for OAuth tokens")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        now = int(time())
        return self._seal({**payload, "t": kind, "iat": now, "exp": now + ttl_seconds, "jti": secrets.token_urlsafe(9)})

    def open_payload(self, token: str, kind: str) -> dict[str, Any]:
        payload = self._open_raw(token)
        if payload.get("t") != kind:
            raise TokenError("Unexpected sealed payload kind")
        return payload

    # -- internals ---------------------------------------------------------

    def _seal(self, payload: dict[str, Any]) -> str:
        nonce = secrets.token_bytes(_NONCE_BYTES)
        plaintext = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        sealed = nonce + self._aead.encrypt(nonce, plaintext, _AAD)
        return TOKEN_PREFIX + base64.urlsafe_b64encode(sealed).rstrip(b"=").decode("ascii")

    def _open_raw(self, token: str) -> dict[str, Any]:
        if not isinstance(token, str) or not token.startswith(TOKEN_PREFIX):
            raise TokenError("Not a sealed token")
        if len(token) > MAX_TOKEN_LENGTH:
            raise TokenError("Token is too long")
        encoded = token[len(TOKEN_PREFIX):]
        try:
            raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        except (ValueError, TypeError):
            raise TokenError("Malformed token") from None
        if len(raw) <= _NONCE_BYTES:
            raise TokenError("Malformed token")
        try:
            plaintext = self._aead.decrypt(raw[:_NONCE_BYTES], raw[_NONCE_BYTES:], _AAD)
            payload = json.loads(plaintext)
        except (InvalidTag, ValueError, UnicodeDecodeError):
            raise TokenError("Token signature is invalid") from None
        if not isinstance(payload, dict):
            raise TokenError("Malformed token")
        try:
            expires_at = int(payload["exp"])
        except (KeyError, TypeError, ValueError):
            raise TokenError("Malformed token") from None
        if expires_at <= int(time()):
            raise TokenError("Token has expired")
        return payload

    def _open(self, token: str) -> TokenClaims:
        payload = self._open_raw(token)
        try:
            claims = TokenClaims(
                kind=str(payload["t"]),
                credential=str(payload["k"]),
                client_id=str(payload["cid"]),
                resource=payload.get("aud"),
                scope=str(payload.get("scope", "")),
                issued_at=int(payload["iat"]),
                expires_at=int(payload["exp"]),
            )
        except (KeyError, TypeError, ValueError):
            raise TokenError("Malformed token") from None
        if claims.resource is not None and not isinstance(claims.resource, str):
            raise TokenError("Malformed token")
        return claims


def _positive_int_env(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise RuntimeError(f"{name} must be an integer number of seconds") from None
    if value <= 0:
        raise RuntimeError(f"{name} must be a positive number of seconds")
    return value
