from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import html
import json
import logging
import os
import re
import secrets
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from threading import Lock
from time import monotonic, time
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

import httpx2 as httpx
from fastmcp.server.dependencies import get_http_request
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.tools.base import Tool, ToolResult
from mcp.types import TextContent
from starlette.applications import Starlette
from starlette.background import BackgroundTask, BackgroundTasks
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import BaseRoute, Mount, Route

from .cimd import CIMDError, ClientMetadata, ClientMetadataResolver, allowed_cimd_hosts_from_env, is_client_id_url
from .oauth_code_store import (
    CODE_TTL_SECONDS,
    MAX_CODES_PER_API_KEY,
    MAX_PENDING_CODES,
    AuthorizationCode,
    AuthorizationCodeStore,
    OAuthCapacityError,
    RedisAuthorizationCodeStore,
    authorization_code_store_from_env,
)
from .oauth_tokens import SealedTokenCodec, TokenError
from .openapi_auth import AuthError, current_authorization_header
from .posthog_client import OAuthCodeEvent, analytics
from .upstream_oauth import PENDING_LOGIN_TTL_SECONDS, UpstreamOAuthBroker, UpstreamOAuthError, UpstreamOAuthSettings


LOGIN_COOKIE = "__Host-mh-oauth-login"
MAX_FORM_BYTES = 16 * 1024
MAX_REGISTRATION_BYTES = 16 * 1024
MAX_CONCURRENT_VALIDATIONS = 10
API_KEY_VERIFICATION_ERROR = (
    "We couldn't verify this API key. Check that you copied the full key and try again."
)
# ChatGPT uses the stable callback when the server implements issuer
# identification (RFC 9207); older connections and servers without it use the
# per-connection ``/connector/oauth/{callback_id}`` form.
CHATGPT_STABLE_REDIRECT_URI = "https://chatgpt.com/connector_platform_oauth_redirect"
ALLOWED_REDIRECT_URIS = {
    "https://claude.ai/api/mcp/auth_callback",
    "http://localhost:8787/callback",
    CHATGPT_STABLE_REDIRECT_URI,
}
ALLOWED_REDIRECT_URI_PATTERNS = [
    re.compile(r"https://chatgpt\.com/connector/oauth/[A-Za-z0-9_-]{12}"),
]
PKCE_RE = re.compile(r"^[A-Za-z0-9._~-]{43,128}$")
CHALLENGE_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
SCOPE_RE = re.compile(r"^[\x21\x23-\x5b\x5d-\x7e]+$")
MCP_SCOPE = "mcp"
OFFLINE_ACCESS_SCOPE = "offline_access"
SUPPORTED_SCOPES = (MCP_SCOPE, OFFLINE_ACCESS_SCOPE)
ApiKeyValidator = Callable[[str], Awaitable[bool]]
logger = logging.getLogger("uvicorn.error.mcp_oauth")
OAUTH_SECURITY_SCHEMES = [{"type": "oauth2", "scopes": []}]


@dataclass(frozen=True)
class OAuthSettings:
    issuer_url: str | None = None
    resource_url: str | None = None
    api_base_url: str = "https://api.magichour.ai"
    validation_path: str = "/v1/ai-image-generator"

    @classmethod
    def from_env(cls) -> "OAuthSettings":
        return cls(
            issuer_url=os.getenv("MCP_OAUTH_ISSUER_URL"),
            resource_url=os.getenv("MCP_OAUTH_RESOURCE_URL"),
            api_base_url=os.getenv("MAGIC_HOUR_API_BASE_URL", "https://api.magichour.ai"),
            validation_path=os.getenv(
                "MAGIC_HOUR_OAUTH_VALIDATION_PATH",
                "/v1/ai-image-generator",
            ),
        )


class OAuthCompatibilityServer:
    def __init__(
        self,
        *,
        settings: OAuthSettings | None = None,
        api_key_validator: ApiKeyValidator | None = None,
        code_store: AuthorizationCodeStore | RedisAuthorizationCodeStore | None = None,
        token_codec: SealedTokenCodec | None | bool = False,
        client_metadata_resolver: ClientMetadataResolver | None = None,
        upstream: UpstreamOAuthBroker | None | bool = False,
    ) -> None:
        self.settings = settings or OAuthSettings.from_env()
        _validate_settings(self.settings)
        self.codes = code_store or authorization_code_store_from_env()
        self.validate_api_key = api_key_validator or self._validate_api_key
        self._validation_slots = asyncio.Semaphore(MAX_CONCURRENT_VALIDATIONS)
        # ``False`` (the default) means "read MCP_OAUTH_TOKEN_SECRET from the
        # environment"; pass ``None`` explicitly to force legacy raw-key tokens.
        self.token_codec = SealedTokenCodec.from_env() if token_codec is False else token_codec
        self.client_metadata = client_metadata_resolver or ClientMetadataResolver(
            allowed_hosts=allowed_cimd_hosts_from_env()
        )
        if upstream is False:
            upstream_settings = UpstreamOAuthSettings.from_env()
            if upstream_settings is None:
                upstream = None
            elif self.token_codec is None:
                raise RuntimeError("MAGIC_HOUR_OAUTH_* broker mode requires MCP_OAUTH_TOKEN_SECRET")
            else:
                upstream = UpstreamOAuthBroker(upstream_settings, self.token_codec)
        self.upstream = upstream

    @property
    def refresh_tokens_enabled(self) -> bool:
        return self.token_codec is not None

    @property
    def account_login_enabled(self) -> bool:
        """True when users log in with their Magic Hour account (broker mode)."""
        return self.upstream is not None

    def _code_event(self, event: OAuthCodeEvent, code: str) -> BackgroundTask:
        # Capture operation time before the response; send telemetry afterward.
        # The PID also distinguishes workers forked after the store was created.
        return BackgroundTask(
            analytics.capture,
            event,
            {
                "authorization_code_hash": hashlib.sha256(code.encode()).hexdigest(),
                "code_store_id": f"{self.codes.instance_id}:{os.getpid()}",
                "code_ttl_seconds": self.codes.ttl_seconds,
                "occurred_at": time(),
            },
        )

    def routes(self) -> list[Route]:
        routes = [
            Route("/register", self.register, methods=["POST"]),
            Route("/authorize", self.authorize, methods=["GET", "POST"]),
            Route("/token", self.token, methods=["POST"]),
            Route("/.well-known/oauth-authorization-server", self.authorization_server_metadata),
            Route("/.well-known/oauth-protected-resource", self.protected_resource_metadata),
            Route("/.well-known/oauth-protected-resource/mcp", self.protected_resource_metadata),
        ]
        if self.upstream is not None:
            routes.append(Route(self.upstream.callback_path, self.upstream_callback, methods=["GET"]))
        return routes

    async def authorize(self, request: Request) -> Response:
        try:
            params = request.query_params if request.method == "GET" else await _read_form(request)
            authorization, client = await self._validate_authorization_request(params, self.resource(request))
        except OAuthRequestError as error:
            return _oauth_error(error.error, error.description)

        page_params = {
            **authorization,
            "response_type": "code",
            "code_challenge_method": "S256",
            "state": params.get("state"),
        }
        if self.upstream is not None:
            if request.method != "GET":
                return _oauth_error("invalid_request", "Sign in with your Magic Hour account to authorize")
            browser_nonce = secrets.token_urlsafe(32)
            pending = {
                **authorization,
                "browser_nonce_hash": hashlib.sha256(browser_nonce.encode()).hexdigest(),
                "state": params.get("state"),
                "refresh_allowed": self._client_may_refresh(client),
            }
            location = self.upstream.begin_login(issuer=self.issuer(request), pending=pending)
            response = RedirectResponse(location, status_code=303, headers={"Cache-Control": "no-store"})
            response.set_cookie(
                LOGIN_COOKIE, browser_nonce, max_age=PENDING_LOGIN_TTL_SECONDS,
                secure=True, httponly=True, samesite="lax", path="/",
            )
            return response
        if request.method == "GET":
            return _authorization_page(page_params)

        api_key = params.get("api_key", "").strip()
        if not api_key:
            return _authorization_failure(page_params, "api_key_missing", "API key is required.", 400)
        if len(api_key) > 512 or any(character.isspace() for character in api_key):
            return _authorization_failure(page_params, "api_key_rejected", API_KEY_VERIFICATION_ERROR, 401)
        if not await self.codes.has_capacity(api_key):
            return _authorization_failure(page_params, "code_capacity", "Server is busy. Try again.", 503)

        try:
            await asyncio.wait_for(self._validation_slots.acquire(), timeout=0.1)
        except TimeoutError:
            return _authorization_failure(page_params, "validation_capacity", "Server is busy. Try again.", 503)
        try:
            try:
                valid = await self.validate_api_key(api_key)
            finally:
                self._validation_slots.release()
        except httpx.HTTPError:
            return _authorization_failure(
                page_params, "validation_unavailable",
                "Could not validate API key. Try again.",
                503,
            )
        if not valid:
            return _authorization_failure(page_params, "api_key_rejected", API_KEY_VERIFICATION_ERROR, 401)

        try:
            code = await self.codes.issue(
                api_key=api_key,
                client_id=authorization["client_id"],
                redirect_uri=authorization["redirect_uri"],
                code_challenge=authorization["code_challenge"],
                resource=authorization["resource"],
                scope=authorization["scope"] or "",
                refresh_allowed=self._client_may_refresh(client),
            )
        except OAuthCapacityError:
            return _authorization_failure(page_params, "code_capacity", "Server is busy. Try again.", 503)
        return self._authorization_redirect(request, authorization["redirect_uri"], code, params.get("state"))

    def _authorization_redirect(
        self, request: Request, redirect_uri: str, code: str, state: str | None
    ) -> RedirectResponse:
        # RFC 9207: every authorization response names the issuer so clients
        # such as ChatGPT can use one stable callback for every connection.
        location = _add_query(redirect_uri, {"code": code, "state": state, "iss": self.issuer(request)})
        response = RedirectResponse(
            location, status_code=303, headers={"Cache-Control": "no-store"},
            background=self._code_event("oauth_authorization_code_issued", code),
        )
        if self.upstream is not None:
            response.delete_cookie(LOGIN_COOKIE, secure=True, httponly=True, samesite="lax")
        return response

    def _client_may_refresh(self, client: ClientMetadata | None) -> bool:
        if not self.refresh_tokens_enabled:
            return False
        # DCR is stateless (no registry), so registered/pre-shared clients
        # decide by advertising refresh support at the token endpoint; CIMD
        # clients declare it in their metadata document.
        return client is None or client.supports_refresh

    async def upstream_callback(self, request: Request) -> Response:
        """Magic Hour sends the user back here after account login (broker mode)."""
        assert self.upstream is not None
        query = request.query_params
        try:
            pending, verifier = self.upstream.open_pending_login(query.get("state", ""))
        except UpstreamOAuthError as error:
            # Without a valid pending state there is no trustworthy client
            # redirect to send the user back to, so fail in place.
            return _oauth_error(error.error, error.description)

        browser_nonce = request.cookies.get(LOGIN_COOKIE, "")
        expected_hash = pending.get("browser_nonce_hash")
        if not browser_nonce or not isinstance(expected_hash, str) or not _constant_time_equal(
            hashlib.sha256(browser_nonce.encode()).hexdigest(), expected_hash
        ):
            return _oauth_error("invalid_request", "Login must complete in the browser that started it")

        redirect_uri = str(pending.get("redirect_uri", ""))
        client_state = pending.get("state")
        client_state = client_state if isinstance(client_state, str) else None
        if not _valid_server_url(redirect_uri):
            return _oauth_error("invalid_request", "Login session is malformed")

        if query.get("error") or not query.get("code"):
            return self._authorization_error_redirect(
                request, redirect_uri, "access_denied", "Magic Hour login was cancelled or denied", client_state
            )
        try:
            credential = await self.upstream.exchange_code(
                issuer=self.issuer(request), code=query["code"], verifier=verifier
            )
        except UpstreamOAuthError as error:
            return self._authorization_error_redirect(request, redirect_uri, error.error, error.description, client_state)

        try:
            code = await self.codes.issue(
                api_key=credential,
                client_id=str(pending.get("client_id", "")),
                redirect_uri=redirect_uri,
                code_challenge=str(pending.get("code_challenge", "")),
                resource=pending.get("resource") if isinstance(pending.get("resource"), str) else None,
                scope=str(pending.get("scope") or ""),
                refresh_allowed=bool(pending.get("refresh_allowed")),
            )
        except OAuthCapacityError:
            return self._authorization_error_redirect(
                request, redirect_uri, "temporarily_unavailable", "Server is busy. Try again.", client_state
            )
        return self._authorization_redirect(request, redirect_uri, code, client_state)

    def _authorization_error_redirect(
        self, request: Request, redirect_uri: str, error: str, description: str, state: str | None
    ) -> RedirectResponse:
        location = _add_query(
            redirect_uri,
            {"error": error, "error_description": description, "state": state, "iss": self.issuer(request)},
        )
        response = RedirectResponse(
            location,
            status_code=303,
            headers={"Cache-Control": "no-store"},
            background=BackgroundTask(
                analytics.capture, "oauth_request_failed",
                {"stage": "upstream_login", "reason": error, "http_status": 303},
            ),
        )
        response.delete_cookie(LOGIN_COOKIE, secure=True, httponly=True, samesite="lax")
        return response

    async def register(self, request: Request) -> Response:
        metadata: dict[str, Any] | None = None
        try:
            metadata = await _read_json(request)
            redirect_uris = _validate_client_metadata(metadata)
        except OAuthRequestError as error:
            logger.warning(
                "registration_rejected error=%s metadata_keys=%s metadata=%s",
                error.error,
                sorted(metadata) if metadata else [],
                _registration_log_metadata(metadata),
            )
            return _registration_error(error.error, error.description)

        requested_grants = metadata.get("grant_types", ["authorization_code"])
        grant_types = ["authorization_code"]
        if self.refresh_tokens_enabled and "refresh_token" in requested_grants:
            grant_types.append("refresh_token")
        return JSONResponse(
            {
                "client_id": secrets.token_urlsafe(32),
                "client_id_issued_at": int(time()),
                "redirect_uris": redirect_uris,
                "token_endpoint_auth_method": "none",
                "grant_types": grant_types,
                "response_types": ["code"],
            },
            status_code=201,
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )

    async def token(self, request: Request) -> Response:
        try:
            params = await _read_form(request)
        except OAuthRequestError as error:
            return _token_rejection("malformed_form", error.error, error.description)

        grant_type = params.get("grant_type")
        if grant_type == "refresh_token":
            return self._refresh_access_token(request, params)
        if grant_type != "authorization_code":
            return _token_rejection(
                "unsupported_grant_type",
                "unsupported_grant_type",
                "grant_type must be authorization_code or refresh_token",
            )

        code = params.get("code", "")
        authorization = await self.codes.get(code)
        if authorization is None:
            return _token_rejection(
                "code_invalid_or_expired",
                "invalid_grant",
                "Authorization code is invalid or expired",
                background=self._code_event("oauth_authorization_code_lookup_missed", code),
            )

        if not _constant_time_equal(params.get("client_id", ""), authorization.client_id):
            return _token_rejection(
                "client_mismatch",
                "invalid_grant",
                "Authorization code does not match client",
            )
        if not _constant_time_equal(params.get("redirect_uri", ""), authorization.redirect_uri):
            return _token_rejection(
                "redirect_uri_mismatch",
                "invalid_grant",
                "Authorization code does not match redirect_uri",
            )
        token_resource = params.get("resource")
        if authorization.resource:
            resource_mismatch = not token_resource or not _same_resource(
                token_resource,
                authorization.resource,
            )
        else:
            resource_mismatch = bool(token_resource) and not _same_resource(
                token_resource,
                self.resource(request),
            )
        if resource_mismatch:
            return _token_rejection(
                "resource_mismatch",
                "invalid_grant",
                "Authorization code does not match resource",
            )

        verifier = params.get("code_verifier", "")
        if not PKCE_RE.fullmatch(verifier) or not hmac.compare_digest(
            _pkce_challenge(verifier), authorization.code_challenge
        ):
            return _token_rejection("pkce_failed", "invalid_grant", "PKCE verification failed")

        if await self.codes.consume(code) != authorization:
            return _token_rejection(
                "code_already_consumed",
                "invalid_grant",
                "Authorization code is invalid or expired",
            )

        return JSONResponse(
            self._token_response(
                credential=authorization.api_key,
                client_id=authorization.client_id,
                resource=authorization.resource or self.resource(request),
                scope=authorization.scope,
                refresh_allowed=authorization.refresh_allowed,
            ),
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
            background=self._code_event("oauth_connection_completed", code),
        )

    def _token_response(
        self,
        *,
        credential: str,
        client_id: str,
        resource: str | None,
        scope: str,
        refresh_allowed: bool,
    ) -> dict[str, Any]:
        if self.token_codec is None:
            # Legacy mode: the credential itself is the bearer token. Enable
            # MCP_OAUTH_TOKEN_SECRET to stop exposing it to OAuth clients.
            legacy: dict[str, Any] = {"access_token": credential, "token_type": "Bearer"}
            if scope:
                legacy["scope"] = scope
            return legacy
        issued = self.token_codec.issue(
            credential=credential, client_id=client_id, resource=resource, scope=scope
        )
        response: dict[str, Any] = {
            "access_token": issued.access_token,
            "token_type": "Bearer",
            "expires_in": issued.expires_in,
        }
        if scope:
            response["scope"] = scope
        if refresh_allowed:
            response["refresh_token"] = issued.refresh_token
        return response

    def _refresh_access_token(self, request: Request, params: Mapping[str, str]) -> Response:
        if self.token_codec is None:
            return _token_rejection(
                "unsupported_grant_type",
                "unsupported_grant_type",
                "refresh_token grant is not enabled",
            )
        try:
            claims = self.token_codec.open_refresh_token(params.get("refresh_token", ""))
        except TokenError:
            return _token_rejection("refresh_token_invalid", "invalid_grant", "Refresh token is invalid or expired")
        if not _constant_time_equal(params.get("client_id", ""), claims.client_id):
            return _token_rejection("client_mismatch", "invalid_grant", "Refresh token does not match client")
        token_resource = params.get("resource")
        if token_resource and claims.resource and not _same_resource(token_resource, claims.resource):
            return _token_rejection("resource_mismatch", "invalid_grant", "Refresh token does not match resource")
        requested_scope = params.get("scope")
        if requested_scope is not None:
            granted = set(claims.scope.split())
            if not set(requested_scope.split()) <= granted:
                return _token_rejection("scope_exceeded", "invalid_scope", "Requested scope exceeds the granted scope")
        # Rotation: every refresh mints a new pair; the previous refresh token
        # stays valid until its own expiry because the store is stateless.
        return JSONResponse(
            self._token_response(
                credential=claims.credential,
                client_id=claims.client_id,
                resource=claims.resource or self.resource(request),
                scope=claims.scope if requested_scope is None else " ".join(dict.fromkeys(requested_scope.split())),
                refresh_allowed=True,
            ),
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )

    async def authorization_server_metadata(self, request: Request) -> Response:
        issuer = self.issuer(request)
        grant_types = ["authorization_code"]
        if self.refresh_tokens_enabled:
            grant_types.append("refresh_token")
        return JSONResponse(
            {
                "issuer": issuer,
                "authorization_endpoint": f"{issuer}/authorize",
                "token_endpoint": f"{issuer}/token",
                "registration_endpoint": f"{issuer}/register",
                "response_types_supported": ["code"],
                "grant_types_supported": grant_types,
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": ["none"],
                "scopes_supported": list(SUPPORTED_SCOPES),
                # RFC 9207 issuer identification: unlocks ChatGPT's stable callback.
                "authorization_response_iss_parameter_supported": True,
                # Client ID Metadata Documents: ChatGPT's preferred client model.
                "client_id_metadata_document_supported": True,
            }
        )

    async def protected_resource_metadata(self, request: Request) -> Response:
        issuer = self.issuer(request)
        return JSONResponse(
            {
                "resource": self.resource(request),
                "authorization_servers": [issuer],
                "bearer_methods_supported": ["header"],
            }
        )

    def issuer(self, request: Request) -> str:
        return (self.settings.issuer_url or str(request.base_url)).rstrip("/")

    def resource(self, request: Request) -> str:
        return (self.settings.resource_url or self.issuer(request)).rstrip("/")

    async def _validate_authorization_request(
        self,
        params: Mapping[str, str],
        expected_resource: str,
    ) -> tuple[dict[str, str | None], ClientMetadata | None]:
        client_id = params.get("client_id", "")
        redirect_uri = params.get("redirect_uri", "")
        challenge = params.get("code_challenge", "")
        resource = params.get("resource")
        scope = params.get("scope")

        if params.get("response_type") != "code":
            raise OAuthRequestError("unsupported_response_type", "response_type must be code")
        if not _valid_client_id(client_id):
            raise OAuthRequestError("invalid_request", "Invalid client or redirect_uri")

        client: ClientMetadata | None = None
        if is_client_id_url(client_id):
            try:
                client = await self.client_metadata.resolve(client_id)
            except CIMDError as error:
                logger.warning("cimd_rejected reason=%s", error)
                raise OAuthRequestError("invalid_client", "Client metadata document is invalid") from None
            if not client.allows_redirect(redirect_uri):
                raise OAuthRequestError("invalid_request", "Invalid client or redirect_uri")
        elif not _allowed_redirect_uri(redirect_uri):
            raise OAuthRequestError("invalid_request", "Invalid client or redirect_uri")

        if params.get("code_challenge_method") != "S256" or not CHALLENGE_RE.fullmatch(challenge):
            raise OAuthRequestError("invalid_request", "PKCE S256 code_challenge is required")
        if resource and not _same_resource(resource, expected_resource):
            raise OAuthRequestError("invalid_target", "Unknown resource")
        if scope is not None:
            scope = _validate_scope(scope)

        return (
            {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "code_challenge": challenge,
                "resource": resource,
                "scope": scope,
            },
            client,
        )

    async def _validate_api_key(self, api_key: str) -> bool:
        async with httpx.AsyncClient(base_url=self.settings.api_base_url, timeout=10.0) as client:
            response = await client.post(
                self.settings.validation_path,
                headers={"Authorization": f"Bearer {api_key}"},
                json={},
            )
        # Empty body cannot create a project or spend credits. The documented
        # endpoint returns 400 only after bearer authentication succeeds.
        if response.status_code == 400:
            return True
        if response.status_code in {401, 403, 404}:
            return False
        response.raise_for_status()
        return False


class MCPBearerChallengeMiddleware:
    """Preserve HTTP auth challenges while allowing public MCP discovery."""

    def __init__(self, app: Any, oauth_server: OAuthCompatibilityServer) -> None:
        self.app = app
        self.oauth_server = oauth_server

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        if scope.get("method") in {"OPTIONS", "POST"}:
            await self.app(scope, receive, send)
            return

        authorization = next(
            (value.decode("latin-1") for name, value in scope.get("headers", []) if name.lower() == b"authorization"),
            None,
        )
        header = authorization or ""
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            if (
                authorization is None
                and scope.get("method") == "GET"
                and scope.get("path") == "/"
                and _accepts_html(scope)
            ):
                response = _setup_page_redirect()
                await response(scope, receive, send)
                return
            request = Request(scope)
            issuer = self.oauth_server.issuer(request)
            response = JSONResponse(
                {"error": "unauthorized"},
                status_code=401,
                headers={
                    "WWW-Authenticate": (
                        f'Bearer resource_metadata="{issuer}/.well-known/oauth-protected-resource"'
                    )
                },
            )
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)


class _OAuthListedTool(Tool):
    def to_mcp_tool(self, **overrides: Any):
        tool = super().to_mcp_tool(**overrides)
        tool.meta = {**(tool.meta or {}), "securitySchemes": OAUTH_SECURITY_SCHEMES}
        return tool


class MCPToolOAuthMiddleware(Middleware):
    """Advertise OAuth during discovery and challenge unauthenticated tool calls."""

    async def on_list_tools(self, context: MiddlewareContext, call_next: Any):
        tools = await call_next(context)
        return [
            _OAuthListedTool(**{name: getattr(tool, name) for name in Tool.model_fields})
            for tool in tools
        ]

    async def on_call_tool(self, context: MiddlewareContext, call_next: Any) -> ToolResult:
        try:
            current_authorization_header()
        except AuthError:
            issuer = (
                OAuthSettings.from_env().issuer_url or str(get_http_request().base_url)
            ).rstrip("/")
            challenge = (
                f'Bearer resource_metadata="{issuer}/.well-known/oauth-protected-resource", '
                'error="invalid_token", error_description="Authentication required"'
            )
            return ToolResult(
                content=[TextContent(type="text", text="Authentication required.")],
                meta={"mcp/www_authenticate": [challenge]},
                is_error=True,
            )
        return await call_next(context)


def _accepts_html(scope: Mapping[str, Any]) -> bool:
    accept_values = (
        value.decode("latin-1")
        for name, value in scope.get("headers", [])
        if name.lower() == b"accept"
    )
    for item in ",".join(accept_values).split(","):
        media_type, *parameters = item.split(";")
        if media_type.strip().lower() != "text/html":
            continue
        quality = 1.0
        for parameter in parameters:
            name, separator, value = parameter.partition("=")
            if separator and name.strip().lower() == "q":
                try:
                    quality = float(value.strip())
                except ValueError:
                    quality = 0.0
        if quality > 0:
            return True
    return False


def _setup_page_redirect() -> RedirectResponse:
    return RedirectResponse(
        "https://magichour.ai/mcp",
        status_code=302,
        headers={"Cache-Control": "no-store", "Vary": "Accept"},
    )


class OAuthRequestError(Exception):
    def __init__(self, error: str, description: str) -> None:
        self.error = error
        self.description = description
        super().__init__(description)


def create_oauth_compatibility_app(
    mcp_app: Any,
    *,
    settings: OAuthSettings | None = None,
    api_key_validator: ApiKeyValidator | None = None,
    public_routes: Sequence[BaseRoute] = (),
) -> Starlette:
    oauth = OAuthCompatibilityServer(
        settings=settings,
        api_key_validator=api_key_validator,
    )
    protected_mcp = MCPBearerChallengeMiddleware(mcp_app, oauth)
    return Starlette(
        routes=[*oauth.routes(), *public_routes, Mount("/", app=protected_mcp)],
        lifespan=mcp_app.lifespan,
    )


async def _read_form(request: Request) -> dict[str, str]:
    content_length = request.headers.get("content-length")
    if content_length and (not content_length.isdigit() or int(content_length) > MAX_FORM_BYTES):
        raise OAuthRequestError("invalid_request", "Request body is too large")
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > MAX_FORM_BYTES:
            raise OAuthRequestError("invalid_request", "Request body is too large")
        body.extend(chunk)
    try:
        parsed = parse_qs(bytes(body).decode("utf-8"), keep_blank_values=True, max_num_fields=20)
    except (UnicodeDecodeError, ValueError):
        raise OAuthRequestError("invalid_request", "Malformed form body") from None
    if any(len(values) != 1 for values in parsed.values()):
        raise OAuthRequestError("invalid_request", "OAuth parameters must not be repeated")
    return {name: values[0] for name, values in parsed.items()}


async def _read_json(request: Request) -> dict[str, Any]:
    content_length = request.headers.get("content-length")
    if content_length and (
        not content_length.isdigit() or int(content_length) > MAX_REGISTRATION_BYTES
    ):
        raise OAuthRequestError("invalid_client_metadata", "Request body is too large")
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > MAX_REGISTRATION_BYTES:
            raise OAuthRequestError("invalid_client_metadata", "Request body is too large")
        body.extend(chunk)
    try:
        value = json.loads(bytes(body))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise OAuthRequestError("invalid_client_metadata", "Malformed JSON body") from None
    if not isinstance(value, dict):
        raise OAuthRequestError("invalid_client_metadata", "Registration body must be an object")
    return value


def _validate_client_metadata(metadata: Mapping[str, Any]) -> list[str]:
    redirect_uris = metadata.get("redirect_uris")
    if (
        not isinstance(redirect_uris, list)
        or not redirect_uris
        or len(redirect_uris) > 10
        or any(not isinstance(uri, str) or not _allowed_redirect_uri(uri) for uri in redirect_uris)
        or len(set(redirect_uris)) != len(redirect_uris)
    ):
        raise OAuthRequestError("invalid_redirect_uri", "redirect_uris must contain valid unique URIs")
    if metadata.get("token_endpoint_auth_method", "none") != "none":
        raise OAuthRequestError("invalid_client_metadata", "Only public clients are supported")
    grant_types = metadata.get("grant_types", ["authorization_code"])
    if (
        not isinstance(grant_types, list)
        or "authorization_code" not in grant_types
        or any(not isinstance(grant_type, str) for grant_type in grant_types)
        or len(grant_types) != len(set(grant_types))
        or any(grant_type not in {"authorization_code", "refresh_token"} for grant_type in grant_types)
    ):
        raise OAuthRequestError("invalid_client_metadata", "Only authorization_code is supported")
    if metadata.get("response_types", ["code"]) != ["code"]:
        raise OAuthRequestError("invalid_client_metadata", "Only code response_type is supported")
    return redirect_uris


def _registration_log_metadata(metadata: Mapping[str, Any] | None) -> dict[str, Any]:
    if metadata is None:
        return {}
    safe: dict[str, Any] = {}
    for name in (
        "redirect_uris",
        "token_endpoint_auth_method",
        "grant_types",
        "response_types",
        "application_type",
        "client_name",
    ):
        if name not in metadata:
            continue
        value = metadata[name]
        if name == "redirect_uris" and isinstance(value, list):
            safe[name] = [_safe_redirect_uri_for_log(uri) for uri in value[:10]]
        elif isinstance(value, list):
            safe[name] = [_safe_log_text(item) for item in value[:10]]
        else:
            safe[name] = _safe_log_text(value)
    return safe


def _safe_log_text(value: Any) -> str:
    if not isinstance(value, str):
        return f"<{type(value).__name__}>"
    return "".join(character if 0x20 <= ord(character) < 0x7F else "?" for character in value)[:512]


def _safe_redirect_uri_for_log(value: Any) -> str:
    uri = re.split(r"[?#]", _safe_log_text(value), maxsplit=1)[0]
    return re.sub(r"(^[A-Za-z][A-Za-z0-9+.-]*://)[^/@]*@", r"\1<credentials>@", uri)


def _allowed_redirect_uri(uri: str) -> bool:
    return uri in ALLOWED_REDIRECT_URIS or any(
        pattern.fullmatch(uri) for pattern in ALLOWED_REDIRECT_URI_PATTERNS
    )


def _valid_client_id(client_id: str) -> bool:
    return 0 < len(client_id) <= 512 and client_id.isascii() and all(
        0x20 < ord(character) < 0x7F for character in client_id
    )


def _validate_scope(scope: str) -> str:
    requested = scope.split(" ") if scope else []
    if len(requested) > 10 or any(not SCOPE_RE.fullmatch(item) for item in requested):
        raise OAuthRequestError("invalid_scope", "Malformed scope")
    unknown = [item for item in requested if item not in SUPPORTED_SCOPES]
    if unknown:
        raise OAuthRequestError("invalid_scope", "Requested scope is not supported")
    return " ".join(dict.fromkeys(requested))


def _authorization_page(
    authorization: Mapping[str, str | None],
    error: str | None = None,
    *,
    status_code: int = 200,
) -> HTMLResponse:
    script_nonce = secrets.token_urlsafe(18)
    fields = "".join(
        f'<input type="hidden" name="{html.escape(name)}" value="{html.escape(value or "")}">'
        for name, value in authorization.items()
        if value is not None
    )
    error_html = (
        f'<p class="error" id="api-key-error" role="alert">'
        f"{html.escape(error)}</p>"
        if error
        else ""
    )
    error_attributes = ' aria-invalid="true" aria-describedby="api-key-error"' if error else ""
    body = f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>Connect to Magic Hour MCP</title>
<style>
  :root {{
    color-scheme: dark;
    --background: hsl(234.55 31.43% 6.86%);
    --foreground: white;
    --card: hsl(235.71 25.93% 10.59%);
    --card-foreground: white;
    --primary: hsl(259.29 100% 50%);
    --primary-foreground: white;
    --muted: hsl(235.71 21.21% 12.94%);
    --muted-foreground: hsl(235 11.11% 57.65%);
    --border: hsl(232.17 22.77% 19.8%);
    --input: hsl(236 19% 15%);
    --ring: white;
    --destructive: hsl(0 100% 68.24%);
    --radius: .625rem;
    font-family: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; min-height: 100vh; min-height: 100dvh; display: grid; place-items: center;
    padding: 24px; color: var(--foreground); background: var(--background);
  }}
  .card {{
    width: min(100%, 440px); padding: 36px; color: var(--card-foreground); background: var(--card);
    border: 1px solid var(--border); border-radius: var(--radius); box-shadow: 0 12px 32px rgba(0, 0, 0, .24);
  }}
  .brand {{
    display: flex; align-items: center; gap: 9px; margin-bottom: 30px;
    color: var(--card-foreground); font-size: 14px; font-weight: 650;
  }}
  .brand-logo {{ width: 24px; height: 24px; flex: 0 0 auto; border-radius: calc(var(--radius) - .1875rem); }}
  h1 {{ margin: 0; font-size: 24px; line-height: 1.2; letter-spacing: -.025em; }}
  .intro {{ margin: 12px 0 26px; color: var(--muted-foreground); font-size: 14px; line-height: 1.55; }}
  .error {{ margin: 8px 0 0; color: var(--destructive); font-size: 12px; line-height: 1.5; }}
  .field-header {{ display: flex; align-items: baseline; justify-content: space-between; flex-wrap: wrap; gap: 6px 16px; margin-bottom: 8px; }}
  label {{ font-size: 13px; font-weight: 650; }}
  .field-header a {{ color: var(--muted-foreground); font-size: 12px; text-underline-offset: 3px; }}
  .field-header a:hover {{ color: var(--foreground); }}
  .field-header a:focus-visible {{ outline: 2px solid var(--ring); outline-offset: 2px; border-radius: 2px; }}
  .api-key-control {{ position: relative; }}
  #api-key {{
    width: 100%; height: 46px; padding: 0 68px 0 13px; color: var(--foreground); background: var(--input);
    border: 1px solid var(--border); border-radius: var(--radius); outline: none; font: inherit;
  }}
  #api-key::placeholder {{ color: var(--muted-foreground); opacity: 1; }}
  #api-key:focus-visible {{ border-color: var(--ring); box-shadow: 0 0 0 2px var(--ring); }}
  input[aria-invalid="true"] {{ border-color: var(--destructive); }}
  .visibility-toggle {{
    position: absolute; top: 7px; right: 7px; width: auto; min-height: 32px; padding: 0 9px;
    border: 0; border-radius: calc(var(--radius) - .1875rem); color: var(--muted-foreground);
    background: transparent; font: inherit; font-size: 12px; font-weight: 650; cursor: pointer;
  }}
  .visibility-toggle:hover {{ color: var(--foreground); background: var(--muted); }}
  .visibility-toggle:focus-visible {{ outline: 2px solid var(--ring); outline-offset: 1px; }}
  .connect-button {{
    width: 100%; min-height: 46px; margin-top: 22px; display: inline-flex; align-items: center;
    justify-content: center; border: 0; border-radius: var(--radius);
    color: var(--primary-foreground); background: var(--primary);
    font-family: inherit; font-size: 14px; font-weight: 650; line-height: 1.25; cursor: pointer;
  }}
  .connect-button:not(:disabled):hover {{ box-shadow: inset 0 0 0 1px var(--primary-foreground); }}
  .connect-button:focus-visible {{ outline: 2px solid var(--ring); outline-offset: 3px; }}
  .connect-button:disabled {{ cursor: wait; opacity: .72; }}
  .button-label, .button-loading {{
    font-family: inherit; font-size: inherit; font-weight: inherit; line-height: inherit;
  }}
  .button-label {{ display: inline-flex; align-items: center; justify-content: center; }}
  .button-loading {{ display: inline-flex; align-items: center; justify-content: center; gap: 8px; }}
  .button-label[hidden], .button-loading[hidden] {{ display: none; }}
  .spinner {{
    width: 14px; height: 14px; border: 2px solid currentColor; border-right-color: transparent;
    border-radius: 50%; animation: spin .7s linear infinite;
  }}
  @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
  @media (prefers-reduced-motion: reduce) {{ .spinner {{ animation: none; }} }}
  @media (max-width: 480px) {{ body {{ padding: 16px; }} .card {{ padding: 28px 24px; }} }}
</style>
</head><body>
<main class="card">
  <div class="brand"><img class="brand-logo" src="/favicon.ico" alt="" width="24" height="24">Magic Hour</div>
  <h1>Connect to Magic Hour MCP</h1>
  <p class="intro">Enter your API key to use Magic Hour tools.</p>
  <form id="authorization-form" method="post" action="" autocomplete="off">{fields}
    <div class="field-header">
      <label for="api-key">API key</label>
      <a href="https://magichour.ai/developer?tab=api-keys" target="_blank" rel="noopener noreferrer">Create your API key</a>
    </div>
    <div class="api-key-control">
      <input id="api-key" name="api_key" type="password" placeholder="mhk_live_…" required autocomplete="new-password" autocapitalize="none" spellcheck="false" data-1p-ignore="true" data-lpignore="true" data-bwignore="true" autofocus{error_attributes}>
      <button id="api-key-visibility" class="visibility-toggle" type="button" aria-label="Show API key" aria-pressed="false">Show</button>
    </div>
    {error_html}
    <button id="connect-button" class="connect-button" type="submit">
      <span class="button-label">Connect</span>
      <span class="button-loading" hidden><span class="spinner" aria-hidden="true"></span><span>Connecting…</span></span>
    </button>
  </form>
</main>
<script nonce="{script_nonce}">
  const form = document.getElementById("authorization-form");
  const apiKeyInput = document.getElementById("api-key");
  const visibilityButton = document.getElementById("api-key-visibility");
  const connectButton = document.getElementById("connect-button");
  const label = connectButton.querySelector(".button-label");
  const loading = connectButton.querySelector(".button-loading");
  visibilityButton.addEventListener("click", () => {{
    const revealing = apiKeyInput.type === "password";
    apiKeyInput.type = revealing ? "text" : "password";
    visibilityButton.textContent = revealing ? "Hide" : "Show";
    visibilityButton.setAttribute("aria-label", revealing ? "Hide API key" : "Show API key");
    visibilityButton.setAttribute("aria-pressed", String(revealing));
  }});
  form.addEventListener("submit", () => {{
    connectButton.disabled = true;
    connectButton.setAttribute("aria-busy", "true");
    label.hidden = true;
    loading.hidden = false;
  }});
</script>
</body></html>"""
    return HTMLResponse(
        body,
        status_code=status_code,
        headers={
            "Cache-Control": "no-store",
            "Content-Security-Policy": (
                "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; "
                f"script-src 'nonce-{script_nonce}'; base-uri 'none'; frame-ancestors 'none'"
            ),
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        },
    )


def _token_error(error: str, description: str) -> JSONResponse:
    return JSONResponse(
        {"error": error, "error_description": description},
        status_code=400,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


def _authorization_failure(
    params: Mapping[str, str | None], reason: str, error: str, status_code: int
) -> HTMLResponse:
    response = _authorization_page(params, error, status_code=status_code)
    response.background = BackgroundTask(
        analytics.capture, "oauth_request_failed",
        {"stage": "authorize", "reason": reason, "http_status": status_code},
    )
    return response


def _token_rejection(
    reason: str, error: str, description: str, *, background: BackgroundTask | None = None
) -> JSONResponse:
    logger.warning("token_rejected reason=%s", reason)
    tasks = BackgroundTasks([background] if background is not None else [])
    tasks.add_task(
        analytics.capture, "oauth_request_failed",
        {"stage": "token", "reason": reason, "http_status": 400},
    )
    response = _token_error(error, description)
    response.background = tasks
    return response


def _oauth_error(error: str, description: str) -> JSONResponse:
    return JSONResponse(
        {"error": error, "error_description": description}, status_code=400,
        background=BackgroundTask(
            analytics.capture, "oauth_request_failed",
            {"stage": "authorize", "reason": error, "http_status": 400},
        ),
    )


def _registration_error(
    error: str,
    description: str,
    *,
    status_code: int = 400,
) -> JSONResponse:
    return JSONResponse(
        {"error": error, "error_description": description},
        status_code=status_code,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        background=BackgroundTask(
            analytics.capture, "oauth_request_failed",
            {"stage": "register", "reason": error, "http_status": status_code},
        ),
    )


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _add_query(uri: str, values: Mapping[str, str | None]) -> str:
    parts = urlsplit(uri)
    query = parse_qs(parts.query, keep_blank_values=True)
    for name, value in values.items():
        if value is not None:
            query[name] = [value]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query, doseq=True), ""))


def _same_resource(left: str, right: str) -> bool:
    try:
        left_parts = urlsplit(left)
        right_parts = urlsplit(right)
    except ValueError:
        return False
    return (
        left_parts.scheme.lower(),
        left_parts.netloc.lower(),
        left_parts.path.rstrip("/"),
        left_parts.query,
    ) == (
        right_parts.scheme.lower(),
        right_parts.netloc.lower(),
        right_parts.path.rstrip("/"),
        right_parts.query,
    )


def _constant_time_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def _valid_server_url(uri: str) -> bool:
    parts = urlsplit(uri)
    if not parts.scheme or not parts.netloc or parts.query or parts.fragment or parts.username or parts.password:
        return False
    if parts.scheme == "https":
        return True
    return parts.scheme == "http" and parts.hostname in {"localhost", "127.0.0.1", "::1"}


def _validate_settings(settings: OAuthSettings) -> None:
    for name, value in (
        ("MCP_OAUTH_ISSUER_URL", settings.issuer_url),
        ("MCP_OAUTH_RESOURCE_URL", settings.resource_url),
        ("MAGIC_HOUR_API_BASE_URL", settings.api_base_url),
    ):
        if value and not _valid_server_url(value):
            raise RuntimeError(f"{name} must be an HTTPS URL (or localhost HTTP)")
    if not settings.validation_path.startswith("/") or settings.validation_path.startswith("//"):
        raise RuntimeError("MAGIC_HOUR_OAUTH_VALIDATION_PATH must be a relative absolute-path")
