from __future__ import annotations

import jsonschema
import mcp.types as mt
from fastmcp import FastMCP
from fastmcp.exceptions import McpError
from typing import Any


def install_structured_tool_errors(mcp: FastMCP) -> None:
    entry = mcp._mcp_server.get_request_handler("tools/call")
    if entry is None:
        raise RuntimeError("FastMCP tools/call handler is not registered")

    async def handle(context: Any, params: mt.CallToolRequestParams) -> mt.CallToolResult:
        tool = await mcp.get_tool(params.name)
        if tool is None:
            raise _invalid_params(f"Unknown tool: {params.name!r}")

        # OpenAPI-generated schemas omit additionalProperties; an unknown arg on a
        # parameterless GET would otherwise be sent upstream as a request body.
        schema = {"additionalProperties": False, **tool.parameters}
        try:
            jsonschema.validate(params.arguments or {}, schema)
        except jsonschema.ValidationError as error:
            raise _invalid_params(
                f"Invalid arguments for tool {params.name!r}: {error.message}"
            ) from error

        return await entry.handler(context, params)

    mcp._mcp_server.add_request_handler("tools/call", entry.params_type, handle)


def _invalid_params(message: str) -> McpError:
    return McpError(code=mt.INVALID_PARAMS, message=message)
