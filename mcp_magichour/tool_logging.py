from __future__ import annotations

import json
import logging
import re
from typing import Any

import mcp.types as mt
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools.base import ToolResult

logger = logging.getLogger("uvicorn.error.mcp_tools")
MAX_STRING_LENGTH = 200
_SECRET_KEYS = {
    "apikey",
    "authorization",
    "password",
    "prompt",
    "secret",
    "token",
}


def _safe_tool_arguments(value: Any) -> Any:
    if isinstance(value, dict):
        safe: dict[str, Any] = {}
        for key, item in value.items():
            normalized_key = re.sub(r"[^a-z0-9]", "", str(key).lower())
            if (
                normalized_key in _SECRET_KEYS
                or normalized_key.endswith(("url", "urls", "filepath", "filepaths"))
            ):
                safe[str(key)] = "[redacted]"
            else:
                safe[str(key)] = _safe_tool_arguments(item)
        return safe
    if isinstance(value, list):
        return [_safe_tool_arguments(item) for item in value]
    if isinstance(value, str) and len(value) > MAX_STRING_LENGTH:
        return f"{value[:MAX_STRING_LENGTH]}…"
    return value


class ToolCallLoggingMiddleware(Middleware):
    """Log tool names and safe diagnostic arguments without credentials or media URLs."""

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        name = context.message.name
        arguments = json.dumps(
            _safe_tool_arguments(context.message.arguments or {}),
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        logger.info("tool_call_started name=%s arguments=%s", name, arguments)
        try:
            result = await call_next(context)
        except Exception as error:
            logger.warning(
                "tool_call_failed name=%s exception_type=%s arguments=%s",
                name,
                type(error).__name__,
                arguments,
            )
            raise
        logger.info("tool_call_completed name=%s is_error=%s", name, result.is_error)
        if name in {"wait_for_image_project", "wait_for_video_project", "wait_for_audio_project"}:
            project = result.structured_content
            if isinstance(project, dict):
                status = project.get("status")
                if status not in {"draft", "queued", "rendering", "complete", "error", "canceled", "timeout"}:
                    status = "unknown"
                downloads = project.get("downloads")
                error = project.get("error")
                error_code = error.get("code") if isinstance(error, dict) else None
                if not isinstance(error_code, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", error_code):
                    error_code = "unknown" if error else "none"
                logger.info(
                    "media_project_result name=%s status=%s download_count=%s inline_media_count=%s has_error=%s error_code=%s",
                    name,
                    status,
                    len(downloads) if isinstance(downloads, list) else 0,
                    sum(item.type in {"image", "audio"} for item in result.content),
                    bool(error),
                    error_code,
                )
        return result
