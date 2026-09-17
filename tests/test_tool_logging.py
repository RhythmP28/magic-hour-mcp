import logging
import unittest

import mcp.types as mt
from fastmcp.server.middleware import MiddlewareContext
from fastmcp.tools.base import ToolResult

from mcp_magichour.tool_logging import ToolCallLoggingMiddleware


LOGGER_NAME = "uvicorn.error.mcp_tools"


class ToolCallLoggingTests(unittest.IsolatedAsyncioTestCase):
    async def test_project_result_logs_status_without_private_result_fields(self):
        context = MiddlewareContext(
            message=mt.CallToolRequestParams(name="wait_for_image_project", arguments={"id": "test-job"}),
            method="tools/call",
        )
        result = ToolResult(
            content="private error message",
            structured_content={
                "status": "error",
                "downloads": [{"url": "https://videos.magichour.ai/private?signature=secret"}],
                "error": {"message": "private error message", "code": "insufficient_credits"},
            },
            is_error=True,
        )

        async def complete(_context):
            return result

        with self.assertLogs(LOGGER_NAME, level=logging.INFO) as captured:
            actual = await ToolCallLoggingMiddleware().on_call_tool(context, complete)
        self.assertIs(actual, result)
        output = "\n".join(captured.output)
        self.assertIn(
            "status=error download_count=1 inline_media_count=0 has_error=True error_code=insufficient_credits",
            output,
        )
        for private in ("private error message", "signature=secret"):
            self.assertNotIn(private, output)

    async def test_project_result_log_rejects_free_form_error_codes(self):
        context = MiddlewareContext(
            message=mt.CallToolRequestParams(name="wait_for_video_project", arguments={"id": "test-job"}),
            method="tools/call",
        )
        result = ToolResult(
            content="failed",
            structured_content={"status": "error", "error": {"code": "secret token value here"}},
            is_error=True,
        )

        async def complete(_context):
            return result

        with self.assertLogs(LOGGER_NAME, level=logging.INFO) as captured:
            await ToolCallLoggingMiddleware().on_call_tool(context, complete)
        output = "\n".join(captured.output)
        self.assertIn("has_error=True error_code=unknown", output)
        self.assertNotIn("secret token value", output)

    async def test_failed_tool_logs_safe_diagnostic_arguments(self):
        middleware = ToolCallLoggingMiddleware()
        context = MiddlewareContext(
            message=mt.CallToolRequestParams(
                name="ai_image_generator_create_image",
                arguments={
                    "model": "default",
                    "resolution": "640px",
                    "style": {"prompt": "private user prompt", "tool": "general"},
                    "source_url": "https://example.test/private?signature=secret",
                    "api_key": "sk_secret",
                },
            ),
            method="tools/call",
        )

        async def fail(_context):
            raise ValueError("upstream failed")

        with self.assertLogs(LOGGER_NAME, level=logging.INFO) as captured:
            with self.assertRaisesRegex(ValueError, "upstream failed"):
                await middleware.on_call_tool(context, fail)

        output = "\n".join(captured.output)
        self.assertIn("tool_call_started", output)
        self.assertIn("tool_call_failed", output)
        self.assertIn('"model":"default"', output)
        self.assertIn('"tool":"general"', output)
        self.assertIn('"prompt":"[redacted]"', output)
        self.assertIn('"source_url":"[redacted]"', output)
        self.assertIn('"api_key":"[redacted]"', output)
        self.assertNotIn("private user prompt", output)
        self.assertNotIn("signature=secret", output)
        self.assertNotIn("sk_secret", output)


if __name__ == "__main__":
    unittest.main()
