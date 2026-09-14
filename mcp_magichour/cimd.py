"""Client ID Metadata Documents (CIMD) for OAuth clients such as ChatGPT.

With CIMD the OAuth ``client_id`` *is* an HTTPS URL that serves a JSON document
describing the client (its redirect URIs, grant types and token endpoint auth
methods). ChatGPT publishes ``https://chatgpt.com/oauth/client.json`` and, for
servers without issuer identification, per-connection documents under
``https://chatgpt.com/oauth/{callback_id}/client.json``. Every ChatGPT user
shares the same document, so a server that supports CIMD works for arbitrary
installs without per-connection registration.

The resolver only fetches documents from an operator-approved list of hosts,
never follows redirects, bounds response size and time, and caches results so
the authorization endpoint does not fetch on every request.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from threading import Lock
from time import monotonic
from typing import Any
from urllib.parse import urlsplit

import httpx


DEFAULT_ALLOWED_HOSTS = ("chatgpt.com",)
DEFAULT_TIMEOUT_SECONDS = 5.0
DEFAULT_MAX_BYTES = 16 * 1024
DEFAULT_CACHE_TTL_SECONDS = 300
MAX_CLIENT_ID_LENGTH = 512
MAX_REDIRECT_URIS = 10
SUPPORTED_GRANT_TYPES = {"authorization_code", "refresh_token"}
Fetcher = Callable[[str], "Any"]


class CIMDError(Exception):
    """The client metadata document could not be resolved or is invalid."""


@dataclass(frozen=True)
class ClientMetadata:
    client_id: str
    redirect_uris: tuple[str, ...]
    grant_types: tuple[str, ...]
    client_name: str | None = None

    def allows_redirect(self, redirect_uri: str) -> bool:
        return redirect_uri in self.redirect_uris

    @property
    def supports_refresh(self) -> bool:
        return "refresh_token" in self.grant_types


def is_client_id_url(client_id: str) -> bool:
    return client_id.startswith("https://")


def allowed_cimd_hosts_from_env() -> tuple[str, ...]:
    raw = os.getenv("MCP_OAUTH_CIMD_ALLOWED_HOSTS", "")
    extra = tuple(host.strip().lower() for host in raw.split(",") if host.strip())
    return tuple(dict.fromkeys((*DEFAULT_ALLOWED_HOSTS, *extra)))


class ClientMetadataResolver:
    def __init__(
        self,
        *,
        allowed_hosts: Sequence[str] = DEFAULT_ALLOWED_HOSTS,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        max_bytes: int = DEFAULT_MAX_BYTES,
        cache_ttl_seconds: float = DEFAULT_CACHE_TTL_SECONDS,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.allowed_hosts = tuple(host.lower() for host in allowed_hosts)
        self.timeout_seconds = timeout_seconds
        self.max_bytes = max_bytes
        self.cache_ttl_seconds = cache_ttl_seconds
        self._transport = transport
        self._cache: dict[str, tuple[float, ClientMetadata]] = {}
        self._lock = Lock()

    def validate_client_id(self, client_id: str) -> None:
        if len(client_id) > MAX_CLIENT_ID_LENGTH or not client_id.isascii():
            raise CIMDError("client_id URL is too long")
        try:
            parts = urlsplit(client_id)
            port = parts.port
        except ValueError:
            raise CIMDError("client_id URL is malformed") from None
        if parts.scheme != "https" or not parts.hostname:
            raise CIMDError("client_id must be an https URL")
        if parts.username or parts.password or parts.query or parts.fragment or port is not None:
            raise CIMDError("client_id URL must not contain credentials, query, fragment, or port")
        if not parts.path or parts.path == "/":
            raise CIMDError("client_id URL must include a document path")
        host = parts.hostname.lower()
        if not any(host == allowed or host.endswith(f".{allowed}") for allowed in self.allowed_hosts):
            raise CIMDError("client_id host is not an approved OAuth client host")

    async def resolve(self, client_id: str) -> ClientMetadata:
        self.validate_client_id(client_id)
        now = monotonic()
        with self._lock:
            cached = self._cache.get(client_id)
            if cached and cached[0] > now:
                return cached[1]

        document = await self._fetch(client_id)
        metadata = parse_client_metadata(client_id, document)
        with self._lock:
            self._cache[client_id] = (monotonic() + self.cache_ttl_seconds, metadata)
        return metadata

    async def _fetch(self, client_id: str) -> Any:
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout_seconds,
                follow_redirects=False,
                transport=self._transport,
                headers={"Accept": "application/json", "User-Agent": "magic-hour-mcp-oauth/1.0"},
            ) as client:
                async with client.stream("GET", client_id) as response:
                    if response.status_code != 200:
                        raise CIMDError("client metadata document is unavailable")
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > self.max_bytes:
                            raise CIMDError("client metadata document is too large")
        except httpx.HTTPError:
            raise CIMDError("client metadata document could not be fetched") from None
        try:
            return json.loads(bytes(body))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise CIMDError("client metadata document is not valid JSON") from None


def parse_client_metadata(client_id: str, document: Any) -> ClientMetadata:
    if not isinstance(document, dict):
        raise CIMDError("client metadata document must be a JSON object")
    if document.get("client_id") != client_id:
        raise CIMDError("client metadata document client_id does not match its URL")

    redirect_uris = document.get("redirect_uris")
    if (
        not isinstance(redirect_uris, list)
        or not redirect_uris
        or len(redirect_uris) > MAX_REDIRECT_URIS
        or any(not isinstance(uri, str) or not _https_redirect(uri) for uri in redirect_uris)
        or len(set(redirect_uris)) != len(redirect_uris)
    ):
        raise CIMDError("client metadata document redirect_uris are invalid")

    grant_types = document.get("grant_types", ["authorization_code"])
    if (
        not isinstance(grant_types, list)
        or "authorization_code" not in grant_types
        or any(not isinstance(grant, str) or grant not in SUPPORTED_GRANT_TYPES for grant in grant_types)
    ):
        raise CIMDError("client metadata document grant_types are unsupported")

    # Public-client PKCE is the only token endpoint auth method this server
    # offers, so the client must be able to use ``none``.
    methods = document.get("token_endpoint_auth_methods_supported")
    single = document.get("token_endpoint_auth_method")
    supports_none = (isinstance(methods, list) and "none" in methods) or single == "none"
    if methods is None and single is None:
        supports_none = True
    if not supports_none:
        raise CIMDError("client metadata document does not allow public-client (none) authentication")

    client_name = document.get("client_name")
    return ClientMetadata(
        client_id=client_id,
        redirect_uris=tuple(redirect_uris),
        grant_types=tuple(dict.fromkeys(grant_types)),
        client_name=client_name if isinstance(client_name, str) else None,
    )


def _https_redirect(uri: str) -> bool:
    try:
        parts = urlsplit(uri)
        parts.port
    except ValueError:
        return False
    return (
        parts.scheme == "https"
        and bool(parts.netloc)
        and not parts.fragment
        and not parts.username
        and not parts.password
    )
