import json
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlsplit

import httpx2 as httpx
from starlette.applications import Starlette

from mcp_magichour.oauth_code_store import (
    MAX_CODES_PER_API_KEY,
    OAuthCapacityError,
    RedisAuthorizationCodeStore,
)
from mcp_magichour.oauth_compat import OAuthCompatibilityServer, OAuthSettings, _pkce_challenge

CLIENT_ID = "magic-hour-mcp"
REDIRECT_URI = "https://claude.ai/api/mcp/auth_callback"
RESOURCE = "https://mcp.example/mcp"
VERIFIER = "v" * 64
CHALLENGE = _pkce_challenge(VERIFIER)
REST_URL = "https://fake-redis.example"
REST_TOKEN = "test-rest-token"
TOKEN_SECRET = "unit-test-token-secret-0123456789abcdef"


class FakeRedis:
    """In-memory stand-in for the Upstash Redis REST pipeline endpoint."""

    def __init__(self):
        self.data: dict[str, str] = {}
        self.commands: list[list[str]] = []
        self.authorizations: list[str] = []

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.authorizations.append(request.headers.get("Authorization", ""))
        assert request.url.path == "/pipeline"
        results = []
        for command in json.loads(request.content):
            self.commands.append(command)
            results.append({"result": self.execute(command)})
        return httpx.Response(200, json=results)

    def execute(self, command: list[str]):
        name, *args = command
        if name == "SET":
            if "NX" in args and args[0] in self.data:
                return None
            self.data[args[0]] = args[1]
            return "OK"
        if name == "GET":
            return self.data.get(args[0])
        if name == "GETDEL":
            return self.data.pop(args[0], None)
        if name == "INCR":
            value = int(self.data.get(args[0], "0")) + 1
            self.data[args[0]] = str(value)
            return value
        if name == "DECR":
            value = int(self.data.get(args[0], "0")) - 1
            self.data[args[0]] = str(value)
            return value
        if name == "EXPIRE":
            return 1
        raise AssertionError(f"unexpected Redis command {command}")


def make_store(fake: FakeRedis) -> RedisAuthorizationCodeStore:
    return RedisAuthorizationCodeStore(
        REST_URL, REST_TOKEN, TOKEN_SECRET, transport=fake.transport()
    )


class RedisAuthorizationCodeStoreTests(unittest.IsolatedAsyncioTestCase):
    async def issue(self, store, api_key="sk_valid"):
        return await store.issue(
            api_key=api_key,
            client_id=CLIENT_ID,
            redirect_uri=REDIRECT_URI,
            code_challenge=CHALLENGE,
            resource=RESOURCE,
            scope="mcp",
            refresh_allowed=True,
        )

    async def test_roundtrip_is_sealed_and_single_use(self):
        fake = FakeRedis()
        store = make_store(fake)
        code = await self.issue(store)

        stored_values = "".join(value for value in fake.data.values())
        self.assertNotIn("sk_valid", stored_values)
        self.assertNotIn(code, "".join(fake.data))
        self.assertTrue(all(auth == f"Bearer {REST_TOKEN}" for auth in fake.authorizations))
        set_command = next(command for command in fake.commands if command[0] == "SET")
        self.assertEqual(set_command[-3:], ["EX", "300", "NX"])

        fetched = await store.get(code)
        consumed = await store.consume(code)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched, consumed)
        self.assertEqual(consumed.api_key, "sk_valid")
        self.assertEqual(consumed.scope, "mcp")
        self.assertTrue(consumed.refresh_allowed)
        self.assertIsNone(await store.consume(code))
        self.assertIsNone(await store.get(code))

    async def test_unknown_and_tampered_codes_return_none(self):
        fake = FakeRedis()
        store = make_store(fake)
        self.assertIsNone(await store.get("missing"))

        code = await self.issue(store)
        key = next(key for key in fake.data if key.startswith("mh:oauth:code:"))
        fake.data[key] = "00" + fake.data[key][2:]
        self.assertIsNone(await store.consume(code))

    async def test_per_key_capacity_is_enforced_and_released_on_consume(self):
        fake = FakeRedis()
        store = make_store(fake)
        codes = [await self.issue(store) for _ in range(MAX_CODES_PER_API_KEY)]
        self.assertFalse(await store.has_capacity("sk_valid"))
        self.assertTrue(await store.has_capacity("sk_other"))
        with self.assertRaises(OAuthCapacityError):
            await self.issue(store)

        await store.consume(codes[0])
        self.assertTrue(await store.has_capacity("sk_valid"))
        await self.issue(store)

    async def test_from_env_requires_complete_configuration(self):
        with mock.patch.dict(
            "os.environ",
            {"UPSTASH_REDIS_REST_URL": REST_URL, "UPSTASH_REDIS_REST_TOKEN": "", "MCP_OAUTH_TOKEN_SECRET": TOKEN_SECRET},
            clear=False,
        ):
            with self.assertRaisesRegex(RuntimeError, "REST URL and REST token"):
                RedisAuthorizationCodeStore.from_env()
        with mock.patch.dict(
            "os.environ",
            {"UPSTASH_REDIS_REST_URL": REST_URL, "UPSTASH_REDIS_REST_TOKEN": REST_TOKEN, "MCP_OAUTH_TOKEN_SECRET": ""},
            clear=False,
        ):
            with self.assertRaisesRegex(RuntimeError, "MCP_OAUTH_TOKEN_SECRET"):
                RedisAuthorizationCodeStore.from_env()
        with mock.patch.dict(
            "os.environ",
            {"UPSTASH_REDIS_REST_URL": "", "UPSTASH_REDIS_REST_TOKEN": "", "KV_REST_API_URL": "", "KV_REST_API_TOKEN": ""},
            clear=False,
        ):
            self.assertIsNone(RedisAuthorizationCodeStore.from_env())


class CrossInstanceTokenExchangeTests(unittest.IsolatedAsyncioTestCase):
    """A code issued by one server instance must redeem on another (Vercel)."""

    async def test_token_endpoint_redeems_code_issued_by_another_instance(self):
        fake = FakeRedis()
        settings = OAuthSettings(issuer_url="https://mcp.example", resource_url=RESOURCE)

        async def validate_api_key(_api_key):
            return True

        authorize_instance = OAuthCompatibilityServer(
            settings=settings, api_key_validator=validate_api_key,
            code_store=make_store(fake), token_codec=None,
        )
        token_instance = OAuthCompatibilityServer(
            settings=settings, api_key_validator=validate_api_key,
            code_store=make_store(fake), token_codec=None,
        )
        self.assertNotEqual(
            authorize_instance.codes.instance_id, token_instance.codes.instance_id
        )

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=Starlette(routes=authorize_instance.routes())),
            base_url="https://mcp.example",
        ) as client:
            response = await client.post("/authorize", data={
                "response_type": "code", "client_id": CLIENT_ID,
                "redirect_uri": REDIRECT_URI, "code_challenge": CHALLENGE,
                "code_challenge_method": "S256", "resource": RESOURCE,
                "state": "client-state", "api_key": "sk_valid",
            })
        self.assertEqual(response.status_code, 303)
        code = parse_qs(urlsplit(response.headers["location"]).query)["code"][0]

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=Starlette(routes=token_instance.routes())),
            base_url="https://mcp.example",
        ) as client:
            exchanged = await client.post("/token", data={
                "grant_type": "authorization_code", "code": code,
                "client_id": CLIENT_ID, "redirect_uri": REDIRECT_URI,
                "code_verifier": VERIFIER, "resource": RESOURCE,
            })
            replayed = await client.post("/token", data={
                "grant_type": "authorization_code", "code": code,
                "client_id": CLIENT_ID, "redirect_uri": REDIRECT_URI,
                "code_verifier": VERIFIER, "resource": RESOURCE,
            })
        self.assertEqual(exchanged.status_code, 200, exchanged.text)
        self.assertEqual(exchanged.json()["access_token"], "sk_valid")
        self.assertEqual(replayed.status_code, 400)
        self.assertEqual(replayed.json()["error"], "invalid_grant")


if __name__ == "__main__":
    unittest.main()
