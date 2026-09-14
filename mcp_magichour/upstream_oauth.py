"""Broker mode: authenticate users with their Magic Hour account instead of a
pasted API key.

OpenAI's plugin guidelines forbid plugins from collecting authentication
secrets such as API keys, so the public ChatGPT plugin cannot ship the API-key
form. In broker mode this server acts as an ordinary OAuth client of Magic
Hour's own authorization server:

    ChatGPT -> GET /authorize (this server)
            -> 303 to Magic Hour login/consent   (MAGIC_HOUR_OAUTH_AUTHORIZE_URL)
            <- Magic Hour redirects to /oauth/callback with a code
            -> this server exchanges it            (MAGIC_HOUR_OAUTH_TOKEN_URL)
            -> mints our sealed tokens, redirects back to ChatGPT with a code

The pending request is sealed into the ``state`` value handed to Magic Hour.
The OAuth route also binds it to a host-only browser cookie and checks that
binding before exchanging the upstream code. Instances sharing the token
secret can complete the callback without a process-local login session.

What Magic Hour's platform has to provide for this mode (outside this repo):

* an OAuth 2.1 authorization-code endpoint with PKCE (S256) that lets a user
  log in and consent, plus a token endpoint;
* a registered client for this MCP server (public with PKCE, or confidential
  with a client secret) whose redirect URI is ``<issuer>/oauth/callback``;
* Magic Hour API acceptance of the resulting user access tokens as
  ``Authorization: Bearer`` credentials, exactly like API keys today.

Until that exists the server keeps the API-key form (the default when the
``MAGIC_HOUR_OAUTH_*`` variables are unset).
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode, urlsplit, urlunsplit

import httpx2 as httpx

from .oauth_tokens import SealedTokenCodec, TokenError


logger = logging.getLogger("uvicorn.error.mcp_oauth")
PENDING_LOGIN_TTL_SECONDS = 10 * 60
PENDING_LOGIN_KIND = "upstream_login"
DEFAULT_CALLBACK_PATH = "/oauth/callback"
DEFAULT_SCOPES = ""
MAX_UPSTREAM_TOKEN_LENGTH = 4096


class UpstreamOAuthError(Exception):
    """The upstream (Magic Hour) authorization step failed."""

    def __init__(self, error: str, description: str) -> None:
        self.error = error
        self.description = description
        super().__init__(description)


@dataclass(frozen=True)
class UpstreamOAuthSettings:
    authorize_url: str
    token_url: str
    client_id: str
    client_secret: str | None = None
    scopes: str = DEFAULT_SCOPES
    callback_path: str = DEFAULT_CALLBACK_PATH

    @classmethod
    def from_env(cls) -> "UpstreamOAuthSettings | None":
        authorize_url = os.getenv("MAGIC_HOUR_OAUTH_AUTHORIZE_URL", "").strip()
        token_url = os.getenv("MAGIC_HOUR_OAUTH_TOKEN_URL", "").strip()
        client_id = os.getenv("MAGIC_HOUR_OAUTH_CLIENT_ID", "").strip()
        if not any((authorize_url, token_url, client_id)):
            return None
        settings = cls(
            authorize_url=authorize_url,
            token_url=token_url,
            client_id=client_id,
            client_secret=os.getenv("MAGIC_HOUR_OAUTH_CLIENT_SECRET", "").strip() or None,
            scopes=os.getenv("MAGIC_HOUR_OAUTH_SCOPES", DEFAULT_SCOPES).strip(),
            callback_path=os.getenv("MAGIC_HOUR_OAUTH_CALLBACK_PATH", DEFAULT_CALLBACK_PATH).strip()
            or DEFAULT_CALLBACK_PATH,
        )
        settings.validate()
        return settings

    def validate(self) -> None:
        for name, value in (
            ("MAGIC_HOUR_OAUTH_AUTHORIZE_URL", self.authorize_url),
            ("MAGIC_HOUR_OAUTH_TOKEN_URL", self.token_url),
        ):
            parts = urlsplit(value)
            if parts.scheme != "https" or not parts.netloc or parts.fragment or parts.username or parts.password:
                raise RuntimeError(f"{name} must be an https URL without credentials or fragment")
        if not self.client_id:
            raise RuntimeError("MAGIC_HOUR_OAUTH_CLIENT_ID is required for broker mode")
        if not self.callback_path.startswith("/") or self.callback_path.startswith("//"):
            raise RuntimeError("MAGIC_HOUR_OAUTH_CALLBACK_PATH must be an absolute path")


class UpstreamOAuthBroker:
    def __init__(
        self,
        settings: UpstreamOAuthSettings,
        codec: SealedTokenCodec,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout_seconds: float = 10.0,
    ) -> None:
        settings.validate()
        self.settings = settings
        self.codec = codec
        self._transport = transport
        self.timeout_seconds = timeout_seconds

    @property
    def callback_path(self) -> str:
        return self.settings.callback_path

    def callback_url(self, issuer: str) -> str:
        return f"{issuer.rstrip('/')}{self.settings.callback_path}"

    def begin_login(self, *, issuer: str, pending: Mapping[str, Any]) -> str:
        """Return the Magic Hour authorization URL that starts the user login."""
        verifier = base64.urlsafe_b64encode(secrets.token_bytes(48)).rstrip(b"=").decode("ascii")
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
        state = self.codec.seal_payload(
            PENDING_LOGIN_KIND,
            {"pending": dict(pending), "verifier": verifier},
            ttl_seconds=PENDING_LOGIN_TTL_SECONDS,
        )
        query = {
            "response_type": "code",
            "client_id": self.settings.client_id,
            "redirect_uri": self.callback_url(issuer),
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        if self.settings.scopes:
            query["scope"] = self.settings.scopes
        parts = urlsplit(self.settings.authorize_url)
        existing = f"{parts.query}&" if parts.query else ""
        return urlunsplit((parts.scheme, parts.netloc, parts.path, existing + urlencode(query), ""))

    def open_pending_login(self, state: str) -> tuple[dict[str, Any], str]:
        """Return (pending authorization request, PKCE verifier) for a state value."""
        try:
            payload = self.codec.open_payload(state, PENDING_LOGIN_KIND)
        except TokenError as error:
            raise UpstreamOAuthError("invalid_request", f"Login session is invalid or expired ({error})") from None
        pending = payload.get("pending")
        verifier = payload.get("verifier")
        if not isinstance(pending, dict) or not isinstance(verifier, str):
            raise UpstreamOAuthError("invalid_request", "Login session is malformed")
        return pending, verifier

    async def exchange_code(self, *, issuer: str, code: str, verifier: str) -> str:
        """Exchange the Magic Hour authorization code for the user's access token."""
        form = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.callback_url(issuer),
            "client_id": self.settings.client_id,
            "code_verifier": verifier,
        }
        auth: tuple[str, str] | None = None
        if self.settings.client_secret:
            auth = (self.settings.client_id, self.settings.client_secret)
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds, transport=self._transport) as client:
                response = await client.post(
                    self.settings.token_url,
                    data=form,
                    auth=auth,
                    headers={"Accept": "application/json"},
                )
        except httpx.HTTPError as error:
            logger.warning("upstream_token_exchange_failed reason=%s", type(error).__name__)
            raise UpstreamOAuthError("temporarily_unavailable", "Magic Hour login is temporarily unavailable") from None
        if response.status_code != 200:
            logger.warning("upstream_token_exchange_rejected status=%s", response.status_code)
            raise UpstreamOAuthError("access_denied", "Magic Hour did not authorize this login")
        try:
            body = response.json()
        except ValueError:
            raise UpstreamOAuthError("server_error", "Magic Hour returned an unreadable token response") from None
        token = body.get("access_token") if isinstance(body, dict) else None
        if (
            not isinstance(token, str)
            or not token
            or len(token) > MAX_UPSTREAM_TOKEN_LENGTH
            or any(character.isspace() for character in token)
            or str(body.get("token_type", "bearer")).lower() != "bearer"
        ):
            raise UpstreamOAuthError("server_error", "Magic Hour returned an unusable access token")
        return token
