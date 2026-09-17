"""Authorization-code storage for the OAuth compatibility server.

Two implementations share one async interface:

- ``AuthorizationCodeStore``: process-local dict, suitable for a single
  long-lived server process (local dev, one uvicorn worker).
- ``RedisAuthorizationCodeStore``: shared store backed by an Upstash-style
  Redis REST endpoint, required on serverless deployments (Vercel) where
  ``/authorize`` and ``/token`` can hit different instances and a
  process-local store yields intermittent ``invalid_grant``.

The Redis payload contains the user's Magic Hour credential, so it is always
sealed with AES-GCM derived from ``MCP_OAUTH_TOKEN_SECRET``; configuring the
Redis store without that secret is a startup error.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from dataclasses import asdict, dataclass
from threading import Lock
from time import monotonic, time
from typing import Any

import httpx2 as httpx
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CODE_TTL_SECONDS = 300
MAX_PENDING_CODES = 1_000
MAX_CODES_PER_API_KEY = 3
_REDIS_TIMEOUT_SECONDS = 5.0
_NONCE_BYTES = 12


class OAuthCapacityError(Exception):
    pass


@dataclass(frozen=True)
class AuthorizationCode:
    api_key: str
    client_id: str
    redirect_uri: str
    code_challenge: str
    resource: str | None
    expires_at: float
    scope: str = ""
    refresh_allowed: bool = False


class AuthorizationCodeStore:
    """Small process-local store for short-lived, single-use codes."""

    def __init__(self, ttl_seconds: int = CODE_TTL_SECONDS) -> None:
        self.ttl_seconds = ttl_seconds
        self.instance_id = secrets.token_hex(16)
        self._codes: dict[str, AuthorizationCode] = {}
        self._lock = Lock()

    async def issue(
        self,
        *,
        api_key: str,
        client_id: str,
        redirect_uri: str,
        code_challenge: str,
        resource: str | None,
        scope: str = "",
        refresh_allowed: bool = False,
    ) -> str:
        code = secrets.token_urlsafe(32)
        now = monotonic()
        authorization_code = AuthorizationCode(
            api_key=api_key,
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            resource=resource,
            expires_at=now + self.ttl_seconds,
            scope=scope,
            refresh_allowed=refresh_allowed,
        )
        with self._lock:
            self._remove_expired(now)
            if sum(value.api_key == api_key for value in self._codes.values()) >= MAX_CODES_PER_API_KEY:
                raise OAuthCapacityError
            if len(self._codes) >= MAX_PENDING_CODES:
                raise OAuthCapacityError
            self._codes[code] = authorization_code
        return code

    async def consume(self, code: str) -> AuthorizationCode | None:
        now = monotonic()
        with self._lock:
            authorization_code = self._codes.pop(code, None)
            self._remove_expired(now)
        if authorization_code is None or authorization_code.expires_at <= now:
            return None
        return authorization_code

    async def get(self, code: str) -> AuthorizationCode | None:
        now = monotonic()
        with self._lock:
            self._remove_expired(now)
            return self._codes.get(code)

    async def has_capacity(self, api_key: str) -> bool:
        now = monotonic()
        with self._lock:
            self._remove_expired(now)
            return (
                len(self._codes) < MAX_PENDING_CODES
                and sum(value.api_key == api_key for value in self._codes.values()) < MAX_CODES_PER_API_KEY
            )

    def _remove_expired(self, now: float) -> None:
        for code, value in list(self._codes.items()):
            if value.expires_at <= now:
                del self._codes[code]


class RedisAuthorizationCodeStore:
    """Single-use code store shared across instances via a Redis REST API.

    Compatible with Upstash Redis and Vercel KV (both speak the Upstash REST
    protocol). Codes are keyed by their SHA-256 so the secret never appears in
    Redis keys or provider logs, values are AES-GCM sealed, expiry is enforced
    by Redis TTLs, and consumption uses the atomic ``GETDEL``.
    """

    def __init__(
        self,
        rest_url: str,
        rest_token: str,
        token_secret: str,
        *,
        ttl_seconds: int = CODE_TTL_SECONDS,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if not rest_url.startswith("https://") and transport is None:
            raise RuntimeError("Authorization-code Redis REST URL must use https")
        self.ttl_seconds = ttl_seconds
        self.instance_id = f"redis:{secrets.token_hex(8)}"
        self._rest_url = rest_url.rstrip("/")
        self._rest_token = rest_token
        # The payload key is derived from the same server secret as sealed
        # bearer tokens, with a distinct context so the keys differ.
        self._aead = AESGCM(
            hashlib.sha256(b"mh-oauth-code-store:" + token_secret.encode("utf-8")).digest()
        )
        self._transport = transport

    @classmethod
    def from_env(cls) -> "RedisAuthorizationCodeStore | None":
        rest_url = (
            os.getenv("UPSTASH_REDIS_REST_URL") or os.getenv("KV_REST_API_URL") or ""
        ).strip()
        rest_token = (
            os.getenv("UPSTASH_REDIS_REST_TOKEN") or os.getenv("KV_REST_API_TOKEN") or ""
        ).strip()
        if not rest_url and not rest_token:
            return None
        if not rest_url or not rest_token:
            raise RuntimeError(
                "Authorization-code Redis store needs both the REST URL and REST token "
                "(UPSTASH_REDIS_REST_URL/UPSTASH_REDIS_REST_TOKEN or KV_REST_API_URL/KV_REST_API_TOKEN)."
            )
        token_secret = os.getenv("MCP_OAUTH_TOKEN_SECRET", "").strip()
        if not token_secret:
            raise RuntimeError(
                "The shared authorization-code store holds user credentials and requires "
                "MCP_OAUTH_TOKEN_SECRET so payloads are sealed at rest."
            )
        return cls(rest_url, rest_token, token_secret)

    async def issue(
        self,
        *,
        api_key: str,
        client_id: str,
        redirect_uri: str,
        code_challenge: str,
        resource: str | None,
        scope: str = "",
        refresh_allowed: bool = False,
    ) -> str:
        code = secrets.token_urlsafe(32)
        authorization_code = AuthorizationCode(
            api_key=api_key,
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            resource=resource,
            # Wall-clock expiry is informational (Redis TTL enforces it) and
            # deterministic, so get() and consume() return equal values.
            expires_at=time() + self.ttl_seconds,
            scope=scope,
            refresh_allowed=refresh_allowed,
        )
        global_count, key_count = await self._reserve_capacity(api_key)
        if global_count > MAX_PENDING_CODES or key_count > MAX_CODES_PER_API_KEY:
            await self._release_capacity(api_key)
            raise OAuthCapacityError
        stored = await self._command(
            "SET", self._code_key(code), self._seal(authorization_code), "EX", str(self.ttl_seconds), "NX"
        )
        if stored != "OK":  # collision or provider refusal; free the slots
            await self._release_capacity(api_key)
            raise OAuthCapacityError
        return code

    async def consume(self, code: str) -> AuthorizationCode | None:
        sealed = await self._command("GETDEL", self._code_key(code))
        authorization_code = self._unseal(sealed)
        if authorization_code is not None:
            await self._release_capacity(authorization_code.api_key)
        return authorization_code

    async def get(self, code: str) -> AuthorizationCode | None:
        return self._unseal(await self._command("GET", self._code_key(code)))

    async def has_capacity(self, api_key: str) -> bool:
        results = await self._pipeline(
            ["GET", self._global_capacity_key()],
            ["GET", self._api_key_capacity_key(api_key)],
        )
        global_count = int(results[0] or 0)
        key_count = int(results[1] or 0)
        return global_count < MAX_PENDING_CODES and key_count < MAX_CODES_PER_API_KEY

    async def _reserve_capacity(self, api_key: str) -> tuple[int, int]:
        results = await self._pipeline(
            ["INCR", self._global_capacity_key()],
            ["EXPIRE", self._global_capacity_key(), str(self.ttl_seconds), "NX"],
            ["INCR", self._api_key_capacity_key(api_key)],
            ["EXPIRE", self._api_key_capacity_key(api_key), str(self.ttl_seconds), "NX"],
        )
        return int(results[0]), int(results[2])

    async def _release_capacity(self, api_key: str) -> None:
        # Best effort: expired-but-unconsumed codes are released when the
        # counter keys themselves expire after one TTL window.
        try:
            await self._pipeline(
                ["DECR", self._global_capacity_key()],
                ["DECR", self._api_key_capacity_key(api_key)],
            )
        except (httpx.HTTPError, RedisCommandError):
            pass

    def _code_key(self, code: str) -> str:
        return f"mh:oauth:code:{hashlib.sha256(code.encode('utf-8')).hexdigest()}"

    def _global_capacity_key(self) -> str:
        return "mh:oauth:codes:pending"

    def _api_key_capacity_key(self, api_key: str) -> str:
        return f"mh:oauth:codes:by-key:{hashlib.sha256(api_key.encode('utf-8')).hexdigest()}"

    def _seal(self, authorization_code: AuthorizationCode) -> str:
        nonce = secrets.token_bytes(_NONCE_BYTES)
        plaintext = json.dumps(asdict(authorization_code), separators=(",", ":")).encode("utf-8")
        return (nonce + self._aead.encrypt(nonce, plaintext, None)).hex()

    def _unseal(self, sealed: Any) -> AuthorizationCode | None:
        if not isinstance(sealed, str) or len(sealed) <= _NONCE_BYTES * 2:
            return None
        try:
            raw = bytes.fromhex(sealed)
            plaintext = self._aead.decrypt(raw[:_NONCE_BYTES], raw[_NONCE_BYTES:], None)
            return AuthorizationCode(**json.loads(plaintext))
        except (ValueError, TypeError, InvalidTag):
            return None

    async def _command(self, *parts: str) -> Any:
        return (await self._pipeline(list(parts)))[0]

    async def _pipeline(self, *commands: list[str]) -> list[Any]:
        async with httpx.AsyncClient(
            timeout=_REDIS_TIMEOUT_SECONDS, transport=self._transport
        ) as client:
            response = await client.post(
                f"{self._rest_url}/pipeline",
                headers={"Authorization": f"Bearer {self._rest_token}"},
                json=list(commands),
            )
        response.raise_for_status()
        results: list[Any] = []
        for entry in response.json():
            if "error" in entry:
                raise RedisCommandError(str(entry["error"]))
            results.append(entry.get("result"))
        return results


class RedisCommandError(Exception):
    pass


def authorization_code_store_from_env() -> AuthorizationCodeStore | RedisAuthorizationCodeStore:
    return RedisAuthorizationCodeStore.from_env() or AuthorizationCodeStore()
