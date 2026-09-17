"""Exercise the sessionless protocol ChatGPT actually sends over HTTP."""

import json
import unittest
from unittest.mock import patch

import httpx2 as httpx

from mcp_magichour.oauth_compat import create_oauth_compatibility_app
from mcp_magichour.oauth_tokens import SealedTokenCodec
from mcp_magichour.openapi_auth import BearerPassthroughAuth
from mcp_magichour.openapi_server import create_mcp, middleware, MCP_APP_VIEW_URI


VERSION = "2026-07-28"
ORIGIN = "https://mcp.example"


class ModernProtocolTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.requests = []
        self.project_status = "complete"

        def upstream(request):
            self.requests.append(request)
            if request.method == "POST" and request.url.path == "/v1/ai-image-generator":
                return httpx.Response(200, json={"id": "test-image-1", "credits_charged": 1})
            if request.method == "GET" and request.url.path == "/v1/image-projects/test-image-1":
                if self.project_status == "error":
                    return httpx.Response(200, json={
                        "id": "test-image-1", "status": "error", "credits_charged": 0,
                        "downloads": [], "error": {"code": "render_failed", "message": "Renderer failed"},
                    })
                return httpx.Response(200, json={
                    "id": "test-image-1", "status": "complete", "credits_charged": 1,
                    "downloads": [{"url": "https://videos.magichour.ai/test-dog.png"}],
                })
            raise AssertionError(f"Unexpected upstream request: {request.method} {request.url.path}")

        def api_client():
            return httpx.AsyncClient(
                base_url="https://api.magichour.ai", auth=BearerPassthroughAuth(),
                transport=httpx.MockTransport(upstream),
            )

        factory = patch("mcp_magichour.openapi_server.build_api_client", side_effect=api_client)
        factory.start()
        self.addCleanup(factory.stop)
        codec = SealedTokenCodec("modern-protocol-test-secret-at-least-32-characters")
        self.token = codec.issue(credential="test-user-key", client_id="chatgpt", resource=ORIGIN).access_token
        token_patch = patch("mcp_magichour.openapi_auth.token_codec", return_value=codec)
        token_patch.start()
        self.addCleanup(token_patch.stop)
        resource_patch = patch("mcp_magichour.openapi_auth.expected_resource", return_value=ORIGIN)
        resource_patch.start()
        self.addCleanup(resource_patch.stop)
        server = create_mcp()
        transport = server.http_app(path="/", middleware=middleware, stateless_http=True)
        app = create_oauth_compatibility_app(transport)
        self.app = app
        self.client = await self.enterAsyncContext(httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url=ORIGIN,
        ))

    async def rpc(self, method, params=None, *, authorized=True, version=VERSION):
        params = dict(params or {})
        params["_meta"] = {
            "io.modelcontextprotocol/protocolVersion": version,
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": {"name": "chatgpt-test", "version": "1"},
        }
        headers = {
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": version, "Mcp-Method": method,
        }
        if "name" in params:
            headers["Mcp-Name"] = params["name"]
        elif "uri" in params:
            headers["Mcp-Name"] = params["uri"]
        if authorized:
            headers["Authorization"] = f"Bearer {self.token}"
        response = await self.client.post("/", headers=headers, json={
            "jsonrpc": "2.0", "id": 1, "method": method, "params": params,
        })
        self.assertNotIn("mcp-session-id", response.headers)
        if "text/event-stream" in response.headers.get("content-type", ""):
            payload = json.loads(next(line[6:] for line in response.text.splitlines() if line.startswith("data: ")))
        else:
            payload = response.json()
        return response.status_code, payload

    async def test_discovery_generation_polling_and_widget_without_initialize(self):
        async with self.app.router.lifespan_context(self.app):
            await self.assert_discovery_generation_polling_and_widget_without_initialize()

    async def assert_discovery_generation_polling_and_widget_without_initialize(self):
        status, payload = await self.rpc("server/discover", authorized=False)
        self.assertEqual(status, 200, payload)
        self.assertIn(VERSION, payload["result"]["supportedVersions"])
        status, payload = await self.rpc("tools/list", authorized=False)
        self.assertEqual(status, 200, payload)
        tools = payload["result"]["tools"]
        self.assertEqual(len(tools), 44)
        for tool in tools:
            self.assertEqual(tool["_meta"]["securitySchemes"], [{"type": "oauth2", "scopes": []}])
            for hint in ("readOnlyHint", "destructiveHint", "openWorldHint"):
                self.assertIsInstance(tool["annotations"][hint], bool)
        wait_tool = next(tool for tool in tools if tool["name"] == "wait_for_image_project")
        self.assertEqual(wait_tool["_meta"]["ui"]["resourceUri"], MCP_APP_VIEW_URI)
        self.assertEqual(wait_tool["_meta"]["openai/outputTemplate"], MCP_APP_VIEW_URI)

        status, payload = await self.rpc("tools/call", {"name": "ping", "arguments": {}})
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["result"]["content"][0]["text"], "pong")

        status, payload = await self.rpc("tools/call", {
            "name": "ai_image_generator_create_image",
            "arguments": {"image_count": 1, "style": {"prompt": "A dog"}},
        })
        self.assertEqual(status, 200, payload)
        self.assertFalse(payload["result"].get("isError"))
        self.assertIn("test-image-1", json.dumps(payload["result"]))
        status, payload = await self.rpc("tools/call", {
            "name": "wait_for_image_project",
            "arguments": {"id": "test-image-1", "include_inline_downloads": False},
        })
        self.assertEqual(status, 200, payload)
        self.assertFalse(payload["result"].get("isError"))
        self.assertIn("test-dog.png", json.dumps(payload["result"]))
        self.assertEqual(len(self.requests), 2)
        self.assertTrue(all(r.headers["authorization"] == "Bearer test-user-key" for r in self.requests))
        self.assertEqual(json.loads(self.requests[0].content)["style"]["prompt"], "A dog")

        status, payload = await self.rpc("resources/read", {"uri": MCP_APP_VIEW_URI}, authorized=False)
        self.assertEqual(status, 200, payload)
        self.assertTrue(payload["result"]["contents"][0]["text"].startswith("<!DOCTYPE html>"))

    async def test_modern_unauthenticated_and_invalid_calls_do_not_reach_api(self):
        async with self.app.router.lifespan_context(self.app):
            await self.assert_modern_unauthenticated_and_invalid_calls_do_not_reach_api()

    async def test_failed_render_is_a_tool_error_with_upstream_details(self):
        self.project_status = "error"
        async with self.app.router.lifespan_context(self.app):
            status, payload = await self.rpc("tools/call", {
                "name": "wait_for_image_project", "arguments": {"id": "test-image-1"},
            })
        self.assertEqual(status, 200, payload)
        result = payload["result"]
        self.assertTrue(result["isError"])
        self.assertIn("Renderer failed", result["content"][0]["text"])
        self.assertEqual(result["structuredContent"]["error"]["code"], "render_failed")
        self.assertEqual(result["structuredContent"]["credits_charged"], 0)
        self.assertEqual([r.method for r in self.requests], ["GET"])

    async def assert_modern_unauthenticated_and_invalid_calls_do_not_reach_api(self):
        status, payload = await self.rpc("tools/call", {"name": "ping", "arguments": {}}, authorized=False)
        self.assertEqual(status, 200, payload)
        self.assertTrue(payload["result"]["isError"])
        self.assertIn("mcp/www_authenticate", payload["result"]["_meta"])
        for name, args in (("ping", {"unexpected": 1}), ("tool_that_does_not_exist", {})):
            _, payload = await self.rpc("tools/call", {"name": name, "arguments": args})
            self.assertEqual(payload["error"]["code"], -32602)
        self.assertEqual(self.requests, [])

    async def test_unknown_protocol_is_rejected_instead_of_silently_downgraded(self):
        async with self.app.router.lifespan_context(self.app):
            await self.assert_unknown_protocol_is_rejected_instead_of_silently_downgraded()

    async def assert_unknown_protocol_is_rejected_instead_of_silently_downgraded(self):
        status, payload = await self.rpc("tools/list", version="2099-01-01")
        self.assertEqual(status, 400)
        self.assertIn("error", payload)
        self.assertEqual(self.requests, [])
