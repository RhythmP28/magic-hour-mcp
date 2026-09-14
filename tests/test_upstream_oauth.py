"""Broker mode: users sign in with their Magic Hour account instead of pasting an API key."""

import os
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import httpx
from starlette.applications import Starlette

from mcp_magichour.oauth_compat import (
    CHATGPT_STABLE_REDIRECT_URI,
    LOGIN_COOKIE,
    OAuthCompatibilityServer,
    OAuthSettings,
    _pkce_challenge,
)
from mcp_magichour.oauth_tokens import SealedTokenCodec
from mcp_magichour.upstream_oauth import UpstreamOAuthBroker, UpstreamOAuthSettings


ISSUER = "https://mcp.example"
SECRET = "broker-test-secret-that-is-at-least-32-characters"
VERIFIER = "c" * 64
CHALLENGE = _pkce_challenge(VERIFIER)
UPSTREAM_AUTHORIZE = "https://magichour.ai/oauth/authorize"
UPSTREAM_TOKEN = "https://magichour.ai/oauth/token"


class FakeMagicHourAuthorizationServer:
    """Minimal stand-in for Magic Hour's future OAuth token endpoint."""

    def __init__(self) -> None:
        self.token_requests: list[dict] = []
        self.next_status = 200
        self.next_body: dict = {"access_token": "mh_user_token_123", "token_type": "Bearer", "expires_in": 3600}

    def transport(self) -> httpx.MockTransport:
        def handler(request: httpx.Request) -> httpx.Response:
            assert str(request.url) == UPSTREAM_TOKEN
            form = {key: values[0] for key, values in parse_qs(request.content.decode()).items()}
            form["_authorization"] = request.headers.get("authorization")
            self.token_requests.append(form)
            return httpx.Response(self.next_status, json=self.next_body)

        return httpx.MockTransport(handler)


class BrokerSettingsTests(unittest.TestCase):
    def test_env_parsing_and_validation(self):
        with patch.dict(os.environ, {}, clear=False):
            for name in list(os.environ):
                if name.startswith("MAGIC_HOUR_OAUTH_"):
                    del os.environ[name]
            self.assertIsNone(UpstreamOAuthSettings.from_env())

        env = {
            "MAGIC_HOUR_OAUTH_AUTHORIZE_URL": UPSTREAM_AUTHORIZE,
            "MAGIC_HOUR_OAUTH_TOKEN_URL": UPSTREAM_TOKEN,
            "MAGIC_HOUR_OAUTH_CLIENT_ID": "mcp-server",
            "MAGIC_HOUR_OAUTH_CLIENT_SECRET": "shh",
            "MAGIC_HOUR_OAUTH_SCOPES": "profile projects:write",
        }
        with patch.dict(os.environ, env):
            settings = UpstreamOAuthSettings.from_env()
        self.assertEqual(settings.client_secret, "shh")
        self.assertEqual(settings.scopes, "profile projects:write")
        self.assertEqual(settings.callback_path, "/oauth/callback")

        with patch.dict(os.environ, {**env, "MAGIC_HOUR_OAUTH_TOKEN_URL": "http://magichour.ai/token"}):
            with self.assertRaises(RuntimeError):
                UpstreamOAuthSettings.from_env()
        with patch.dict(os.environ, {**env, "MAGIC_HOUR_OAUTH_CLIENT_ID": ""}):
            with self.assertRaises(RuntimeError):
                UpstreamOAuthSettings.from_env()

    def test_broker_mode_requires_the_token_secret(self):
        env = {
            "MAGIC_HOUR_OAUTH_AUTHORIZE_URL": UPSTREAM_AUTHORIZE,
            "MAGIC_HOUR_OAUTH_TOKEN_URL": UPSTREAM_TOKEN,
            "MAGIC_HOUR_OAUTH_CLIENT_ID": "mcp-server",
            "MCP_OAUTH_TOKEN_SECRET": "",
        }
        with patch.dict(os.environ, env), self.assertRaises(RuntimeError):
            OAuthCompatibilityServer(settings=OAuthSettings(issuer_url=ISSUER))


class BrokerFlowTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.magic_hour = FakeMagicHourAuthorizationServer()
        self.codec = SealedTokenCodec(SECRET, access_ttl_seconds=3600)
        self.broker = UpstreamOAuthBroker(
            UpstreamOAuthSettings(
                authorize_url=UPSTREAM_AUTHORIZE,
                token_url=UPSTREAM_TOKEN,
                client_id="mcp-server",
                client_secret="shh",
                scopes="profile",
            ),
            self.codec,
            transport=self.magic_hour.transport(),
        )

        async def never_called(api_key):  # pragma: no cover - broker mode skips API-key validation
            raise AssertionError("API key validation must not run in broker mode")

        self.oauth = OAuthCompatibilityServer(
            settings=OAuthSettings(issuer_url=ISSUER, resource_url=ISSUER),
            api_key_validator=never_called,
            token_codec=self.codec,
            upstream=self.broker,
        )
        self.app = Starlette(routes=self.oauth.routes())
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url=ISSUER)

    async def asyncTearDown(self):
        await self.client.aclose()

    def authorization_params(self, **overrides):
        params = {
            "response_type": "code",
            "client_id": "registered-client",
            "redirect_uri": CHATGPT_STABLE_REDIRECT_URI,
            "code_challenge": CHALLENGE,
            "code_challenge_method": "S256",
            "resource": ISSUER,
            "state": "chatgpt-state",
            "scope": "mcp",
        }
        params.update(overrides)
        return params

    async def start_login(self):
        response = await self.client.get("/authorize", params=self.authorization_params())
        self.assertEqual(response.status_code, 303)
        cookie = response.headers["set-cookie"]
        for attribute in ("Secure", "HttpOnly", "SameSite=lax", "Path=/", "Max-Age=600"):
            self.assertIn(attribute, cookie)
        location = urlsplit(response.headers["location"])
        self.assertEqual(f"{location.scheme}://{location.netloc}{location.path}", UPSTREAM_AUTHORIZE)
        query = parse_qs(location.query)
        self.assertEqual(query["client_id"], ["mcp-server"])
        self.assertEqual(query["redirect_uri"], [f"{ISSUER}/oauth/callback"])
        self.assertEqual(query["code_challenge_method"], ["S256"])
        self.assertEqual(query["scope"], ["profile"])
        self.assertTrue(query["state"][0].startswith("mhmcp_v1."))
        return query

    async def test_login_round_trip_mints_sealed_tokens_from_the_account_token(self):
        upstream_query = await self.start_login()

        callback = await self.client.get(
            "/oauth/callback", params={"code": "magic-hour-code", "state": upstream_query["state"][0]}
        )
        self.assertEqual(callback.status_code, 303)
        self.assertNotIn(LOGIN_COOKIE, self.client.cookies)
        location = urlsplit(callback.headers["location"])
        self.assertEqual(f"{location.scheme}://{location.netloc}{location.path}", CHATGPT_STABLE_REDIRECT_URI)
        query = parse_qs(location.query)
        self.assertEqual(query["state"], ["chatgpt-state"])
        self.assertEqual(query["iss"], [ISSUER])
        self.assertIn("code", query)

        exchange = self.magic_hour.token_requests[0]
        self.assertEqual(exchange["grant_type"], "authorization_code")
        self.assertEqual(exchange["code"], "magic-hour-code")
        self.assertEqual(exchange["redirect_uri"], f"{ISSUER}/oauth/callback")
        self.assertTrue(exchange["_authorization"].startswith("Basic "))
        self.assertEqual(_pkce_challenge(exchange["code_verifier"]), upstream_query["code_challenge"][0])

        token = await self.client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": "registered-client",
                "redirect_uri": CHATGPT_STABLE_REDIRECT_URI,
                "code": query["code"][0],
                "code_verifier": VERIFIER,
                "resource": ISSUER,
            },
        )
        self.assertEqual(token.status_code, 200)
        body = token.json()
        self.assertNotIn("mh_user_token_123", token.text)
        self.assertEqual(self.codec.open_access_token(body["access_token"]).credential, "mh_user_token_123")
        self.assertIn("refresh_token", body)

    async def test_denied_or_failed_upstream_login_returns_an_oauth_error_to_the_client(self):
        upstream_query = await self.start_login()
        denied = await self.client.get(
            "/oauth/callback", params={"error": "access_denied", "state": upstream_query["state"][0]}
        )
        query = parse_qs(urlsplit(denied.headers["location"]).query)
        self.assertEqual(query["error"], ["access_denied"])
        self.assertEqual(query["state"], ["chatgpt-state"])
        self.assertEqual(query["iss"], [ISSUER])
        self.assertEqual(self.magic_hour.token_requests, [])

        self.magic_hour.next_status = 400
        upstream_query = await self.start_login()
        failed = await self.client.get(
            "/oauth/callback", params={"code": "bad", "state": upstream_query["state"][0]}
        )
        self.assertEqual(parse_qs(urlsplit(failed.headers["location"]).query)["error"], ["access_denied"])

    async def test_callback_requires_the_initiating_browser_and_clears_cookie(self):
        query = await self.start_login()
        callback_params = {"code": "magic-hour-code", "state": query["state"][0]}
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url=ISSUER) as other:
            for cookies in ({}, {LOGIN_COOKIE: "attacker-nonce"}):
                other.cookies.clear()
                other.cookies.update(cookies)
                rejected = await other.get("/oauth/callback", params=callback_params)
                self.assertEqual(rejected.status_code, 400)
                self.assertNotIn("location", rejected.headers)
        self.assertEqual(self.magic_hour.token_requests, [])
        accepted = await self.client.get("/oauth/callback", params=callback_params)
        self.assertEqual(accepted.status_code, 303)
        replay = await self.client.get("/oauth/callback", params=callback_params)
        self.assertEqual(replay.status_code, 400)
        self.assertEqual(len(self.magic_hour.token_requests), 1)

    async def test_forged_or_expired_state_cannot_complete_a_login(self):
        forged = await self.client.get("/oauth/callback", params={"code": "x", "state": "mhmcp_v1.forged"})
        self.assertEqual(forged.status_code, 400)
        self.assertEqual(forged.json()["error"], "invalid_request")

        other_codec = SealedTokenCodec("some-other-secret-that-is-at-least-32-chars")
        foreign = other_codec.seal_payload("upstream_login", {"pending": {}, "verifier": "v"}, ttl_seconds=60)
        response = await self.client.get("/oauth/callback", params={"code": "x", "state": foreign})
        self.assertEqual(response.status_code, 400)

        access = self.codec.issue(credential="k", client_id="c", resource=ISSUER).access_token
        wrong_kind = await self.client.get("/oauth/callback", params={"code": "x", "state": access})
        self.assertEqual(wrong_kind.status_code, 400)
        self.assertEqual(self.magic_hour.token_requests, [])

    async def test_api_key_form_is_disabled_in_broker_mode(self):
        response = await self.client.post(
            "/authorize", data={**self.authorization_params(), "api_key": "mhk_live_pasted"}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"], "invalid_request")

    async def test_metadata_still_describes_this_server_as_the_authorization_server(self):
        metadata = (await self.client.get("/.well-known/oauth-authorization-server")).json()
        self.assertEqual(metadata["authorization_endpoint"], f"{ISSUER}/authorize")
        self.assertEqual(metadata["token_endpoint"], f"{ISSUER}/token")
        self.assertTrue(metadata["authorization_response_iss_parameter_supported"])


if __name__ == "__main__":
    unittest.main()
