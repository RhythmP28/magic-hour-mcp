"""Production OAuth behaviour required by ChatGPT's current plugin platform.

Covers RFC 9207 issuer identification, the stable ChatGPT callback, Client ID
Metadata Documents (CIMD), sealed access/refresh tokens, scope handling, and
the bearer unwrapping performed before Magic Hour API calls.
"""

import json
import os
import unittest
from time import time
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import httpx2 as httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

from mcp_magichour import openapi_auth
from mcp_magichour.cimd import CIMDError, ClientMetadataResolver, parse_client_metadata
from mcp_magichour.oauth_compat import (
    CHATGPT_STABLE_REDIRECT_URI,
    MCPBearerChallengeMiddleware,
    OAuthCompatibilityServer,
    OAuthSettings,
    _pkce_challenge,
)
from mcp_magichour.oauth_tokens import SealedTokenCodec, TokenError
from mcp_magichour.openapi_auth import AuthError, BearerPassthroughMiddleware, current_authorization_header


ISSUER = "https://mcp.example"
RESOURCE = "https://mcp.example"
SECRET = "unit-test-secret-that-is-at-least-32-characters-long"
VERIFIER = "v" * 64
CHALLENGE = _pkce_challenge(VERIFIER)
CHATGPT_CIMD = "https://chatgpt.com/oauth/client.json"
CHATGPT_CIMD_DOCUMENT = {
    "client_id": CHATGPT_CIMD,
    "client_uri": "https://chatgpt.com/",
    "redirect_uris": [CHATGPT_STABLE_REDIRECT_URI],
    "token_endpoint_auth_method": "private_key_jwt",
    "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "client_name": "ChatGPT",
    "jwks_uri": "https://chatgpt.com/oauth/jwks.json",
}


def cimd_transport(documents: dict[str, dict], counter: list[str] | None = None) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if counter is not None:
            counter.append(str(request.url))
        document = documents.get(str(request.url))
        if document is None:
            return httpx.Response(404, text="missing")
        if isinstance(document, str):
            return httpx.Response(200, content=document.encode(), headers={"content-type": "application/json"})
        return httpx.Response(200, json=document)

    return httpx.MockTransport(handler)


class SealedTokenCodecTests(unittest.TestCase):
    def test_round_trip_and_kinds(self):
        codec = SealedTokenCodec(SECRET, access_ttl_seconds=60, refresh_ttl_seconds=120)
        issued = codec.issue(credential="mhk_live_abc", client_id="client", resource=RESOURCE, scope="mcp")

        self.assertTrue(issued.access_token.startswith("mhmcp_v1."))
        self.assertNotIn("mhk_live_abc", issued.access_token)
        self.assertNotIn("mhk_live_abc", issued.refresh_token)
        self.assertEqual(issued.expires_in, 60)

        access = codec.open_access_token(issued.access_token)
        self.assertEqual((access.kind, access.credential, access.client_id, access.resource, access.scope),
                         ("access", "mhk_live_abc", "client", RESOURCE, "mcp"))
        refresh = codec.open_refresh_token(issued.refresh_token)
        self.assertEqual(refresh.kind, "refresh")
        with self.assertRaises(TokenError):
            codec.open_access_token(issued.refresh_token)
        with self.assertRaises(TokenError):
            codec.open_refresh_token(issued.access_token)

    def test_rejects_tampered_foreign_and_expired_tokens(self):
        codec = SealedTokenCodec(SECRET, access_ttl_seconds=60)
        other = SealedTokenCodec("another-secret-that-is-also-at-least-32-chars")
        token = codec.issue(credential="k", client_id="c", resource=None).access_token

        with self.assertRaises(TokenError):
            other.open_access_token(token)
        with self.assertRaises(TokenError):
            codec.open_access_token(token[:-4] + "AAAA")
        with self.assertRaises(TokenError):
            codec.open_access_token("mhk_live_raw_key")
        with self.assertRaises(TokenError):
            codec.open_access_token("mhmcp_v1.!!!")

        with patch("mcp_magichour.oauth_tokens.time", return_value=time() + 3600):
            with self.assertRaises(TokenError):
                codec.open_access_token(token)

    def test_requires_a_strong_secret_and_positive_ttls(self):
        with self.assertRaises(RuntimeError):
            SealedTokenCodec("short")
        with self.assertRaises(RuntimeError):
            SealedTokenCodec(SECRET, access_ttl_seconds=0)
        with patch.dict(os.environ, {"MCP_OAUTH_TOKEN_SECRET": ""}):
            self.assertIsNone(SealedTokenCodec.from_env())
        with patch.dict(os.environ, {"MCP_OAUTH_TOKEN_SECRET": SECRET, "MCP_OAUTH_ACCESS_TOKEN_TTL": "900"}):
            self.assertEqual(SealedTokenCodec.from_env().access_ttl_seconds, 900)
        with patch.dict(os.environ, {"MCP_OAUTH_TOKEN_SECRET": SECRET, "MCP_OAUTH_ACCESS_TOKEN_TTL": "soon"}):
            with self.assertRaises(RuntimeError):
                SealedTokenCodec.from_env()


class ClientMetadataDocumentTests(unittest.IsolatedAsyncioTestCase):
    async def test_resolves_chatgpt_document_once_and_caches(self):
        fetched: list[str] = []
        resolver = ClientMetadataResolver(transport=cimd_transport({CHATGPT_CIMD: CHATGPT_CIMD_DOCUMENT}, fetched))

        metadata = await resolver.resolve(CHATGPT_CIMD)
        again = await resolver.resolve(CHATGPT_CIMD)

        self.assertEqual(metadata.redirect_uris, (CHATGPT_STABLE_REDIRECT_URI,))
        self.assertTrue(metadata.supports_refresh)
        self.assertTrue(metadata.allows_redirect(CHATGPT_STABLE_REDIRECT_URI))
        self.assertFalse(metadata.allows_redirect("https://chatgpt.com/connector/oauth/abcdefghijkl"))
        self.assertEqual(metadata.client_name, "ChatGPT")
        self.assertEqual(again, metadata)
        self.assertEqual(fetched, [CHATGPT_CIMD])

    async def test_rejects_unapproved_hosts_and_malformed_ids(self):
        resolver = ClientMetadataResolver(transport=cimd_transport({}))
        for client_id in (
            "https://evil.example/client.json",
            "https://chatgpt.com.evil.example/client.json",
            "http://chatgpt.com/oauth/client.json",
            "https://user:pw@chatgpt.com/oauth/client.json",
            "https://chatgpt.com/oauth/client.json?x=1",
            "https://chatgpt.com/",
            "https://chatgpt.com:8443/oauth/client.json",
            "https://chatgpt.com:invalid/oauth/client.json",
            "https://[chatgpt.com/oauth/client.json",
        ):
            with self.subTest(client_id=client_id), self.assertRaises(CIMDError):
                await resolver.resolve(client_id)

    async def test_rejects_documents_that_do_not_match_or_are_unsafe(self):
        mismatched = {**CHATGPT_CIMD_DOCUMENT, "client_id": "https://chatgpt.com/other.json"}
        http_redirect = {**CHATGPT_CIMD_DOCUMENT, "redirect_uris": ["http://chatgpt.com/cb"]}
        no_public_client = {**CHATGPT_CIMD_DOCUMENT, "token_endpoint_auth_methods_supported": ["private_key_jwt"]}
        odd_grant = {**CHATGPT_CIMD_DOCUMENT, "grant_types": ["client_credentials"]}
        for document in (mismatched, http_redirect, no_public_client, odd_grant, ["not", "an", "object"]):
            with self.subTest(document=document), self.assertRaises(CIMDError):
                parse_client_metadata(CHATGPT_CIMD, document)

        huge = json.dumps({**CHATGPT_CIMD_DOCUMENT, "padding": "x" * 20_000})
        resolver = ClientMetadataResolver(transport=cimd_transport({CHATGPT_CIMD: huge}))
        with self.assertRaises(CIMDError):
            await resolver.resolve(CHATGPT_CIMD)
        missing = ClientMetadataResolver(transport=cimd_transport({}))
        with self.assertRaises(CIMDError):
            await missing.resolve(CHATGPT_CIMD)

    def test_allowed_hosts_from_env_adds_operator_hosts(self):
        from mcp_magichour.cimd import allowed_cimd_hosts_from_env

        with patch.dict(os.environ, {"MCP_OAUTH_CIMD_ALLOWED_HOSTS": " Claude.ai, chatgpt.com "}):
            self.assertEqual(allowed_cimd_hosts_from_env(), ("chatgpt.com", "claude.ai"))


class ProductionOAuthFlowTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        async def validate_api_key(api_key):
            return api_key == "mhk_live_valid"

        self.fetched: list[str] = []
        self.codec = SealedTokenCodec(SECRET, access_ttl_seconds=3600, refresh_ttl_seconds=86400)
        self.oauth = OAuthCompatibilityServer(
            settings=OAuthSettings(issuer_url=ISSUER, resource_url=RESOURCE),
            api_key_validator=validate_api_key,
            token_codec=self.codec,
            client_metadata_resolver=ClientMetadataResolver(
                transport=cimd_transport({CHATGPT_CIMD: CHATGPT_CIMD_DOCUMENT}, self.fetched)
            ),
        )

        async def mcp_endpoint(request: Request):
            return JSONResponse({"authorization": request.headers.get("authorization")})

        protected = MCPBearerChallengeMiddleware(Starlette(routes=[Route("/", mcp_endpoint)]), self.oauth)
        self.app = Starlette(routes=[*self.oauth.routes(), Mount("/", protected)])
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url=ISSUER)

    async def asyncTearDown(self):
        await self.client.aclose()

    def authorization_params(self, **overrides):
        params = {
            "response_type": "code",
            "client_id": CHATGPT_CIMD,
            "redirect_uri": CHATGPT_STABLE_REDIRECT_URI,
            "code_challenge": CHALLENGE,
            "code_challenge_method": "S256",
            "resource": RESOURCE,
            "state": "chatgpt-state",
            "scope": "mcp offline_access",
        }
        params.update(overrides)
        return params

    async def authorize(self, **overrides):
        response = await self.client.post(
            "/authorize", data={**self.authorization_params(**overrides), "api_key": "mhk_live_valid"}
        )
        return response

    async def exchange(self, code, **overrides):
        data = {
            "grant_type": "authorization_code",
            "client_id": CHATGPT_CIMD,
            "redirect_uri": CHATGPT_STABLE_REDIRECT_URI,
            "code": code,
            "code_verifier": VERIFIER,
            "resource": RESOURCE,
        }
        data.update(overrides)
        return await self.client.post("/token", data=data)

    async def test_metadata_advertises_issuer_identification_cimd_refresh_and_scopes(self):
        metadata = (await self.client.get("/.well-known/oauth-authorization-server")).json()
        resource = (await self.client.get("/.well-known/oauth-protected-resource")).json()

        self.assertEqual(metadata["issuer"], ISSUER)
        self.assertEqual(resource["authorization_servers"], [ISSUER])
        self.assertTrue(metadata["authorization_response_iss_parameter_supported"])
        self.assertTrue(metadata["client_id_metadata_document_supported"])
        self.assertEqual(metadata["grant_types_supported"], ["authorization_code", "refresh_token"])
        self.assertEqual(metadata["code_challenge_methods_supported"], ["S256"])
        self.assertEqual(metadata["token_endpoint_auth_methods_supported"], ["none"])
        self.assertEqual(metadata["scopes_supported"], ["mcp", "offline_access"])

    async def test_cimd_client_uses_stable_callback_and_receives_iss_and_sealed_tokens(self):
        page = await self.client.get("/authorize", params=self.authorization_params())
        self.assertEqual(page.status_code, 200)
        self.assertIn('name="scope" value="mcp offline_access"', page.text)

        authorized = await self.authorize()
        self.assertEqual(authorized.status_code, 303)
        location = urlsplit(authorized.headers["location"])
        query = parse_qs(location.query)
        self.assertEqual(f"{location.scheme}://{location.netloc}{location.path}", CHATGPT_STABLE_REDIRECT_URI)
        self.assertEqual(query["state"], ["chatgpt-state"])
        self.assertEqual(query["iss"], [ISSUER])
        self.assertEqual(self.fetched, [CHATGPT_CIMD])

        token = await self.exchange(query["code"][0])
        self.assertEqual(token.status_code, 200)
        body = token.json()
        self.assertEqual(body["token_type"], "Bearer")
        self.assertEqual(body["expires_in"], 3600)
        self.assertEqual(body["scope"], "mcp offline_access")
        self.assertTrue(body["access_token"].startswith("mhmcp_v1."))
        self.assertTrue(body["refresh_token"].startswith("mhmcp_v1."))
        self.assertNotIn("mhk_live_valid", json.dumps(body))
        claims = self.codec.open_access_token(body["access_token"])
        self.assertEqual((claims.credential, claims.client_id, claims.resource), ("mhk_live_valid", CHATGPT_CIMD, RESOURCE))

        # Replay of the code fails; the second CIMD authorization reuses the cache.
        replay = await self.exchange(query["code"][0])
        self.assertEqual(replay.json()["error"], "invalid_grant")
        await self.authorize()
        self.assertEqual(self.fetched, [CHATGPT_CIMD])

    async def test_cimd_client_cannot_use_a_callback_outside_its_document(self):
        response = await self.authorize(redirect_uri="https://chatgpt.com/connector/oauth/abcdefghijkl")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"], "invalid_request")

        unknown = await self.authorize(client_id="https://evil.example/client.json", redirect_uri="https://evil.example/cb")
        self.assertEqual(unknown.status_code, 400)
        self.assertEqual(unknown.json()["error"], "invalid_client")

    async def test_opaque_clients_can_use_the_stable_chatgpt_callback(self):
        registration = await self.client.post(
            "/register",
            json={
                "redirect_uris": [CHATGPT_STABLE_REDIRECT_URI],
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
            },
        )
        self.assertEqual(registration.status_code, 201)
        registered = registration.json()
        self.assertEqual(registered["grant_types"], ["authorization_code", "refresh_token"])
        self.assertIsInstance(registered["client_id_issued_at"], int)

        authorized = await self.authorize(client_id=registered["client_id"])
        self.assertEqual(authorized.status_code, 303)
        query = parse_qs(urlsplit(authorized.headers["location"]).query)
        self.assertEqual(query["iss"], [ISSUER])
        token = await self.exchange(query["code"][0], client_id=registered["client_id"])
        self.assertEqual(token.status_code, 200)
        self.assertIn("refresh_token", token.json())

    async def test_refresh_grant_rotates_tokens_and_binds_client(self):
        authorized = await self.authorize()
        code = parse_qs(urlsplit(authorized.headers["location"]).query)["code"][0]
        first = (await self.exchange(code)).json()

        refreshed = await self.client.post(
            "/token",
            data={"grant_type": "refresh_token", "refresh_token": first["refresh_token"], "client_id": CHATGPT_CIMD},
        )
        self.assertEqual(refreshed.status_code, 200)
        second = refreshed.json()
        self.assertNotEqual(second["access_token"], first["access_token"])
        self.assertNotEqual(second["refresh_token"], first["refresh_token"])
        self.assertEqual(second["scope"], "mcp offline_access")
        self.assertEqual(self.codec.open_access_token(second["access_token"]).credential, "mhk_live_valid")

        wrong_client = await self.client.post(
            "/token",
            data={"grant_type": "refresh_token", "refresh_token": first["refresh_token"], "client_id": "someone-else"},
        )
        self.assertEqual(wrong_client.status_code, 400)
        self.assertEqual(wrong_client.json()["error"], "invalid_grant")

        as_refresh = await self.client.post(
            "/token",
            data={"grant_type": "refresh_token", "refresh_token": first["access_token"], "client_id": CHATGPT_CIMD},
        )
        self.assertEqual(as_refresh.json()["error"], "invalid_grant")

        widened = await self.client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": second["refresh_token"],
                "client_id": CHATGPT_CIMD,
                "scope": "mcp offline_access admin",
            },
        )
        self.assertEqual(widened.json()["error"], "invalid_scope")

    async def test_unknown_scope_is_rejected_before_the_page_renders(self):
        response = await self.client.get("/authorize", params=self.authorization_params(scope="mcp admin"))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"], "invalid_scope")

    async def test_refresh_narrows_scopes_in_both_tokens(self):
        authorized = await self.authorize()
        code = parse_qs(urlsplit(authorized.headers["location"]).query)["code"][0]
        first = (await self.exchange(code)).json()
        narrowed = await self.client.post("/token", data={
            "grant_type": "refresh_token", "refresh_token": first["refresh_token"],
            "client_id": CHATGPT_CIMD, "scope": "mcp",
        })
        self.assertEqual(narrowed.status_code, 200)
        body = narrowed.json()
        self.assertEqual(body["scope"], "mcp")
        self.assertEqual(self.codec.open_access_token(body["access_token"]).scope, "mcp")
        self.assertEqual(self.codec.open_refresh_token(body["refresh_token"]).scope, "mcp")
        widened = await self.client.post("/token", data={
            "grant_type": "refresh_token", "refresh_token": body["refresh_token"],
            "client_id": CHATGPT_CIMD, "scope": "mcp offline_access",
        })
        self.assertEqual(widened.json()["error"], "invalid_scope")

    async def test_malformed_token_parameters_fail_without_consuming_code(self):
        authorized = await self.authorize()
        code = parse_qs(urlsplit(authorized.headers["location"]).query)["code"][0]
        for overrides in ({"client_id": "\u2603"}, {"redirect_uri": "https://example.com/\u2603"}, {"resource": "https://[broken"}):
            with self.subTest(overrides=overrides):
                rejected = await self.exchange(code, **overrides)
                self.assertEqual(rejected.status_code, 400)
                self.assertEqual(rejected.json()["error"], "invalid_grant")
        accepted = await self.exchange(code)
        self.assertEqual(accepted.status_code, 200)
        refresh = await self.client.post("/token", data={
            "grant_type": "refresh_token", "refresh_token": accepted.json()["refresh_token"],
            "client_id": "\u2603",
        })
        self.assertEqual(refresh.status_code, 400)

    async def test_malformed_cimd_url_is_an_oauth_error(self):
        for client_id in ("https://chatgpt.com:invalid/client.json", "https://[chatgpt.com/client.json"):
            response = await self.authorize(client_id=client_id)
            self.assertEqual(response.status_code, 400)
            self.assertEqual(response.json()["error"], "invalid_client")

    async def test_legacy_mode_without_secret_keeps_raw_key_tokens_and_no_refresh(self):
        legacy = OAuthCompatibilityServer(
            settings=OAuthSettings(issuer_url=ISSUER, resource_url=RESOURCE),
            api_key_validator=self.oauth.validate_api_key,
            token_codec=None,
        )
        app = Starlette(routes=[*legacy.routes()])
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ISSUER) as client:
            metadata = (await client.get("/.well-known/oauth-authorization-server")).json()
            self.assertEqual(metadata["grant_types_supported"], ["authorization_code"])
            registration = await client.post(
                "/register",
                json={"redirect_uris": [CHATGPT_STABLE_REDIRECT_URI], "grant_types": ["authorization_code", "refresh_token"]},
            )
            self.assertEqual(registration.json()["grant_types"], ["authorization_code"])
            params = self.authorization_params(client_id=registration.json()["client_id"], scope="mcp")
            authorized = await client.post("/authorize", data={**params, "api_key": "mhk_live_valid"})
            code = parse_qs(urlsplit(authorized.headers["location"]).query)["code"][0]
            token = await client.post(
                "/token",
                data={
                    "grant_type": "authorization_code",
                    "client_id": registration.json()["client_id"],
                    "redirect_uri": CHATGPT_STABLE_REDIRECT_URI,
                    "code": code,
                    "code_verifier": VERIFIER,
                    "resource": RESOURCE,
                },
            )
            self.assertEqual(token.json(), {"access_token": "mhk_live_valid", "token_type": "Bearer", "scope": "mcp"})
            refresh = await client.post("/token", data={"grant_type": "refresh_token", "refresh_token": "x", "client_id": "c"})
            self.assertEqual(refresh.json()["error"], "unsupported_grant_type")


class SealedBearerUnwrapTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.codec = SealedTokenCodec(SECRET, access_ttl_seconds=60)
        openapi_auth.configure_token_codec(self.codec)
        self.addCleanup(openapi_auth.configure_token_codec, None)

    async def header_seen_by_tools(self, authorization: str | None, env: dict[str, str] | None = None):
        seen: dict[str, object] = {}

        async def app(scope, receive, send):
            try:
                seen["header"] = current_authorization_header()
            except AuthError as error:
                seen["error"] = str(error)
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b""})

        headers = {"Authorization": authorization} if authorization else {}
        with patch.dict(os.environ, env or {}, clear=False):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=BearerPassthroughMiddleware(app)), base_url="https://mcp.example"
            ) as client:
                await client.post("/", headers=headers)
        return seen

    async def test_sealed_token_is_exchanged_for_the_api_key(self):
        token = self.codec.issue(credential="mhk_live_secret", client_id="c", resource=RESOURCE).access_token
        seen = await self.header_seen_by_tools(f"Bearer {token}", {"MCP_OAUTH_RESOURCE_URL": RESOURCE})
        self.assertEqual(seen, {"header": "Bearer mhk_live_secret"})

    async def test_raw_api_keys_still_pass_through(self):
        seen = await self.header_seen_by_tools("Bearer mhk_live_direct")
        self.assertEqual(seen, {"header": "Bearer mhk_live_direct"})

    async def test_expired_or_foreign_or_wrong_audience_tokens_are_rejected(self):
        token = self.codec.issue(credential="k", client_id="c", resource="https://other.example").access_token
        wrong_audience = await self.header_seen_by_tools(f"Bearer {token}", {"MCP_OAUTH_RESOURCE_URL": RESOURCE})
        self.assertIn("different resource", wrong_audience["error"])

        foreign = SealedTokenCodec("a-different-secret-with-at-least-32-characters").issue(
            credential="k", client_id="c", resource=RESOURCE
        ).access_token
        rejected = await self.header_seen_by_tools(f"Bearer {foreign}")
        self.assertIn("invalid or expired", rejected["error"])

        refresh = self.codec.issue(credential="k", client_id="c", resource=RESOURCE).refresh_token
        as_access = await self.header_seen_by_tools(f"Bearer {refresh}")
        self.assertIn("invalid or expired", as_access["error"])

    async def test_sealed_tokens_are_rejected_when_the_secret_is_not_configured(self):
        token = self.codec.issue(credential="k", client_id="c", resource=RESOURCE).access_token
        openapi_auth.configure_token_codec(None)
        seen = await self.header_seen_by_tools(f"Bearer {token}")
        self.assertIn("not enabled", seen["error"])


if __name__ == "__main__":
    unittest.main()
