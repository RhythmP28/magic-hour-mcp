#!/usr/bin/env python3
"""Verify a deployed Magic Hour MCP server against ChatGPT plugin requirements.

Usage:
    python scripts/verify_chatgpt_readiness.py https://mcp.magichour.ai

Runs read-only or side-effect-free checks (one throwaway DCR registration) and
prints PASS/WARN/FAIL lines. Exit status is 1 if any FAIL occurred. Nothing
here needs credentials; the authenticated path is covered by the unit tests
and by the ChatGPT connection test described in CURRENT-STATUS.md.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.parse
import urllib.request

CHATGPT_STABLE_REDIRECT = "https://chatgpt.com/connector_platform_oauth_redirect"
REQUIRED_ANNOTATIONS = ("readOnlyHint", "openWorldHint", "destructiveHint")
CURRENT_PROTOCOL_VERSION = "2026-07-28"
results: list[tuple[str, str]] = []


def record(level: str, message: str) -> None:
    results.append((level, message))
    print(f"{level:4} {message}")


def http(method: str, url: str, *, body: bytes | None = None, headers: dict | None = None):
    request = urllib.request.Request(url, data=body, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, _lower_keys(response.headers), response.read()
    except urllib.error.HTTPError as error:
        return error.code, _lower_keys(error.headers), error.read()


def _lower_keys(headers) -> dict:
    return {name.lower(): value for name, value in headers.items()}


def json_rpc(base: str, payload: dict, *, token: str | None = None, protocol_version: str | None = None):
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    if protocol_version:
        headers["MCP-Protocol-Version"] = protocol_version
        headers["Mcp-Method"] = payload["method"]
        params = dict(payload.get("params") or {})
        if payload["method"] == "tools/call":
            headers["Mcp-Name"] = params["name"]
        elif payload["method"] == "resources/read":
            headers["Mcp-Name"] = params["uri"]
        params["_meta"] = {
            **params.get("_meta", {}),
            "io.modelcontextprotocol/protocolVersion": protocol_version,
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": {"name": "readiness", "version": "2"},
        }
        payload = {**payload, "params": params}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    status, response_headers, body = http("POST", base + "/", body=json.dumps(payload).encode(), headers=headers)
    text = body.decode("utf-8", "replace")
    message = None
    if "text/event-stream" in response_headers.get("content-type", ""):
        for line in text.splitlines():
            if line.startswith("data: "):
                message = json.loads(line[6:])
                break
    elif text.strip():
        message = json.loads(text)
    return status, response_headers, message


def main(base: str) -> int:
    results.clear()
    base = base.rstrip("/")

    # --- OAuth discovery -------------------------------------------------
    status, _, body = http("GET", f"{base}/.well-known/oauth-protected-resource")
    if status == 200:
        prm = json.loads(body)
        record("PASS", f"protected resource metadata: resource={prm.get('resource')}")
        issuer_list = prm.get("authorization_servers") or []
    else:
        record("FAIL", f"protected resource metadata returned {status}")
        issuer_list = []

    status, _, body = http("GET", f"{base}/.well-known/oauth-authorization-server")
    metadata = json.loads(body) if status == 200 else {}
    if status != 200:
        record("FAIL", f"authorization server metadata returned {status}")
    else:
        record("PASS", f"authorization server metadata: issuer={metadata.get('issuer')}")
        if metadata.get("issuer") not in issuer_list:
            record("FAIL", "issuer does not match protected-resource authorization_servers (required for stable callback)")
        if metadata.get("code_challenge_methods_supported") != ["S256"]:
            record("FAIL", "code_challenge_methods_supported must be exactly ['S256']")
        if metadata.get("authorization_response_iss_parameter_supported") is True:
            record("PASS", "RFC 9207 issuer identification advertised (stable ChatGPT callback)")
        else:
            record("WARN", "authorization_response_iss_parameter_supported missing: ChatGPT will use per-connection callbacks")
        if metadata.get("client_id_metadata_document_supported") is True:
            record("PASS", "CIMD advertised (ChatGPT's preferred client model)")
        else:
            record("WARN", "client_id_metadata_document_supported missing: ChatGPT falls back to DCR")
        if "refresh_token" in (metadata.get("grant_types_supported") or []):
            record("PASS", "refresh_token grant advertised")
        else:
            record("WARN", "refresh_token grant not advertised: ChatGPT sessions cannot be renewed silently")
        if "registration_endpoint" in metadata:
            record("PASS", "DCR endpoint advertised")

    # --- DCR with ChatGPT's stable callback -------------------------------
    status, _, body = http(
        "POST",
        f"{base}/register",
        body=json.dumps(
            {
                "client_name": "readiness-check",
                "redirect_uris": [CHATGPT_STABLE_REDIRECT],
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
            }
        ).encode(),
        headers={"Content-Type": "application/json"},
    )
    if status == 201:
        registration = json.loads(body)
        record("PASS", f"DCR accepts the stable ChatGPT callback (grant_types={registration.get('grant_types')})")
    else:
        record("FAIL", f"DCR with the stable ChatGPT callback returned {status}: {body[:120]!r}")

    # --- Domain verification endpoint ----------------------------------------
    status, headers, body = http("GET", f"{base}/.well-known/openai-apps-challenge")
    if status == 200 and headers.get("content-type", "").startswith("text/plain") and body.strip():
        record("PASS", "openai-apps-challenge serves a plain-text token")
    elif status == 404:
        record("WARN", "openai-apps-challenge not configured yet (set OPENAI_APPS_CHALLENGE_TOKEN before Verify Domain)")
    else:
        record("FAIL", f"openai-apps-challenge returned {status} {headers.get('content-type')}")

    # --- MCP discovery without credentials ----------------------------------
    status, _, message = json_rpc(
        base,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "readiness", "version": "1"}},
        },
    )
    if status == 200 and message and "result" in message:
        record("PASS", f"initialize: server {message['result'].get('serverInfo', {}).get('name')}")
    else:
        record("FAIL", f"initialize returned {status}: {message}")

    status, _, message = json_rpc(base, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    tools = (message or {}).get("result", {}).get("tools", []) if status == 200 else []
    if not tools:
        record("FAIL", f"tools/list returned {status} with no tools: {message}")
    else:
        record("PASS", f"tools/list: {len(tools)} tools")
        missing = [t["name"] for t in tools if any(k not in (t.get("annotations") or {}) for k in REQUIRED_ANNOTATIONS)]
        if missing:
            record("FAIL", f"{len(missing)} tools lack explicit annotations (annotations_required): {missing[:5]}...")
        else:
            record("PASS", "every tool declares readOnlyHint/openWorldHint/destructiveHint")
        no_security = [t["name"] for t in tools if not (t.get("securitySchemes") or (t.get("_meta") or {}).get("securitySchemes"))]
        if no_security:
            record("WARN", f"{len(no_security)} tools have no securitySchemes (ChatGPT tool-level auth UI needs them)")
        else:
            record("PASS", "every tool advertises securitySchemes")
        templates = [t for t in tools if (t.get("_meta") or {}).get("ui")]
        if templates:
            record("PASS", f"{len(templates)} tools reference a UI template")
            missing_alias = [
                t["name"] for t in templates
                if (t.get("_meta") or {}).get("openai/outputTemplate")
                != ((t.get("_meta") or {}).get("ui") or {}).get("resourceUri")
            ]
            if missing_alias:
                record("FAIL", f"UI tools missing openai/outputTemplate alias (ChatGPT will not render the widget): {missing_alias}")
            else:
                record("PASS", "every UI tool carries the openai/outputTemplate alias for ChatGPT")

    status, _, message = json_rpc(
        base, {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "ping", "arguments": {}}}
    )
    challenge = ((message or {}).get("result") or {}).get("_meta", {}).get("mcp/www_authenticate")
    if challenge and 'resource_metadata="' in challenge[0]:
        record("PASS", "unauthenticated tools/call returns the mcp/www_authenticate challenge")
    else:
        record("FAIL", f"unauthenticated tools/call did not return a challenge: {message}")

    status, headers, _ = http("GET", f"{base}/", headers={"Accept": "application/json"})
    if status == 401 and "resource_metadata=" in headers.get("www-authenticate", ""):
        record("PASS", "HTTP 401 challenge carries WWW-Authenticate resource_metadata")
    else:
        record("WARN", f"GET / without auth returned {status} (expected 401 with WWW-Authenticate)")

    # --- Widget domain -----------------------------------------------------
    status, _, message = json_rpc(base, {"jsonrpc": "2.0", "id": 4, "method": "resources/list"})
    resources = (message or {}).get("result", {}).get("resources", []) if status == 200 else []
    ui_resources = [r for r in resources if str(r.get("uri", "")).startswith("ui://")]
    for resource in ui_resources:
        meta = resource.get("_meta") or {}
        domain = (meta.get("ui") or {}).get("domain") or meta.get("openai/widgetDomain")
        if domain:
            record("PASS", f"UI template {resource['uri']} declares widget domain {domain}")
        else:
            record("FAIL", f"UI template {resource['uri']} has no widget domain (required for submission)")
        widget_csp = meta.get("openai/widgetCSP") or {}
        if widget_csp.get("connect_domains") is not None and widget_csp.get("resource_domains") is not None:
            record("PASS", f"UI template {resource['uri']} declares openai/widgetCSP for ChatGPT")
        else:
            record("FAIL", f"UI template {resource['uri']} has no openai/widgetCSP (ChatGPT blocks widget media without it)")

    # Modern MCP has no initialize handshake. Exercise its real HTTP header
    # and per-request envelope; a legacy-only server must fail this check.
    modern = {"protocol_version": CURRENT_PROTOCOL_VERSION}
    status, _, message = json_rpc(base, {"jsonrpc": "2.0", "id": 10, "method": "server/discover"}, **modern)
    discovered = (message or {}).get("result", {})
    record("PASS" if status == 200 and CURRENT_PROTOCOL_VERSION in discovered.get("supportedVersions", []) else "FAIL",
           f"modern server/discover supports {CURRENT_PROTOCOL_VERSION}")
    status, _, message = json_rpc(base, {"jsonrpc": "2.0", "id": 11, "method": "tools/list"}, **modern)
    modern_tools = (message or {}).get("result", {}).get("tools", [])
    record("PASS" if status == 200 and len(modern_tools) == 44 else "FAIL",
           f"modern tools/list: {len(modern_tools)} tools")
    complete = modern_tools and all(
        all(isinstance((tool.get("annotations") or {}).get(key), bool) for key in REQUIRED_ANNOTATIONS)
        and (tool.get("securitySchemes") or (tool.get("_meta") or {}).get("securitySchemes"))
        for tool in modern_tools
    )
    record("PASS" if complete else "FAIL", "modern tool annotations and OAuth metadata")
    status, _, message = json_rpc(base, {
        "jsonrpc": "2.0", "id": 12, "method": "tools/call", "params": {"name": "ping", "arguments": {}},
    }, **modern)
    result = (message or {}).get("result", {})
    record("PASS" if status == 200 and result.get("isError") and result.get("_meta", {}).get("mcp/www_authenticate") else "FAIL",
           "modern unauthenticated tools/call returns OAuth challenge")
    status, _, message = json_rpc(base, {"jsonrpc": "2.0", "id": 13, "method": "resources/list"}, **modern)
    modern_resources = (message or {}).get("result", {}).get("resources", [])
    record("PASS" if status == 200 and any(str(r.get("uri", "")).startswith("ui://") for r in modern_resources) else "FAIL",
           "modern resources/list exposes the result widget")
    for resource in modern_resources:
        if str(resource.get("uri", "")).startswith("ui://"):
            status, _, message = json_rpc(base, {
                "jsonrpc": "2.0", "id": 14, "method": "resources/read", "params": {"uri": resource["uri"]},
            }, **modern)
            contents = (message or {}).get("result", {}).get("contents", [])
            record("PASS" if status == 200 and contents and contents[0].get("text", "").startswith("<!DOCTYPE html>") else "FAIL",
                   "modern resources/read returns the result widget HTML")

    failures = sum(1 for level, _ in results if level == "FAIL")
    warnings = sum(1 for level, _ in results if level == "WARN")
    print(f"\n{len(results) - failures - warnings} passed, {warnings} warnings, {failures} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
