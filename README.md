# Magic Hour MCP Server

OpenAPI-backed MCP server for Magic Hour image, video, and audio generation.

At startup, this server reads `docs/openapi.json` and builds MCP tools with
`FastMCP.from_openapi()`. The OpenAPI spec supplies endpoint coverage, while
Magic Hour MCP policies add agent-facing guidance for async polling, uploads,
and project downloads.

Docs:

- [CURRENT-STATUS.md](CURRENT-STATUS.md) - ChatGPT architecture, deployment, test steps, and public submission blockers
- [Magic Hour agent skills](https://github.com/magichourhq/skills) - media workflows, published examples, and recovery guidance
- `user.md` - hosted endpoint user guide
- `integration-handoff.md` - FastAPI mount checklist
- `docs/detailed-step-by-step-integration.md` - full backend integration guide
- `docs/api-reference.md` - generated API reference

## Setup

```sh
pip install -e .
```

## Run locally

```sh
python main.py
```

Local MCP endpoint:

```text
http://127.0.0.1:8000/
```

This local dev server runs at `/`, not `/mcp`. The host app adds `/mcp` when it mounts the server.

By default, requests go to the production Magic Hour API:

```text
https://api.magichour.ai
```

Tool discovery is public. Tool calls must include your Magic Hour API key:

```text
Authorization: Bearer <magic_hour_api_key>
```

Agents can discover the hosted server card at:

```text
https://mcp.magichour.ai/.well-known/mcp/server-card.json
```

Environment variables:

```sh
MAGIC_HOUR_API_BASE_URL=https://api.magichour.ai
MAGIC_HOUR_OPENAPI_PATH=docs/openapi.json
MCP_OAUTH_ISSUER_URL=https://mcp.magichour.ai
MCP_OAUTH_RESOURCE_URL=https://mcp.magichour.ai

# Sealed OAuth tokens (use a random secret of at least 32 characters)
# MCP_OAUTH_TOKEN_SECRET=<random-secret>
MCP_OAUTH_ACCESS_TOKEN_TTL=28800
MCP_OAUTH_REFRESH_TOKEN_TTL=2592000
# Extra CIMD hosts; chatgpt.com is always allowed
# MCP_OAUTH_CIMD_ALLOWED_HOSTS=another-client.example
MAGIC_HOUR_OAUTH_VALIDATION_PATH=/v1/ai-image-generator

MCP_APP_ORIGIN=https://mcp.magichour.ai
# Defaults to MCP_APP_ORIGIN; use a unique origin for this plugin
MCP_APP_WIDGET_DOMAIN=https://mcp.magichour.ai
# OPENAI_APPS_CHALLENGE_TOKEN=<token-from-the-submission-portal>

# Account login: set all three once Magic Hour exposes OAuth endpoints
# MAGIC_HOUR_OAUTH_AUTHORIZE_URL=https://<auth-host>/authorize
# MAGIC_HOUR_OAUTH_TOKEN_URL=https://<auth-host>/token
# MAGIC_HOUR_OAUTH_CLIENT_ID=<registered-client-id>
# MAGIC_HOUR_OAUTH_CLIENT_SECRET=<optional-client-secret>
# MAGIC_HOUR_OAUTH_SCOPES=<upstream-scopes>
MAGIC_HOUR_OAUTH_CALLBACK_PATH=/oauth/callback
```

Override `MAGIC_HOUR_API_BASE_URL` to use a mock or another API base:

```sh
MAGIC_HOUR_API_BASE_URL=https://api.sideko.dev/v1/mock/magichour/magic-hour/latest python main.py
```

The server supports MCP `2026-07-28` (sessionless `server/discover` and per-request
metadata) and legacy clients using `initialize`. FastMCP, MCP, and httpx2 are pinned
in `pyproject.toml`; install those dependencies together.

## OAuth compatibility

The OAuth shim supports ChatGPT's stable callback with issuer identification,
Client ID Metadata Documents (CIMD), and public-client PKCE. With
`MCP_OAUTH_TOKEN_SECRET` set, it issues sealed access and refresh tokens.
Without it, the legacy mode returns the API key as the access token.
Production requires explicit `MCP_OAUTH_ISSUER_URL` and `MCP_OAUTH_RESOURCE_URL`.

The default login page asks for an API key and is intended for private testing.
Public submission requires account login: configure the three upstream OAuth
URL/client variables above and `MCP_OAUTH_TOKEN_SECRET` to enable the broker.
Magic Hour must provide those endpoints and accept user tokens at its API.
See [CURRENT-STATUS.md](CURRENT-STATUS.md) for the backend contract and remaining
limits, including process-local authorization codes and refresh-token revocation.

Public OAuth clients can use the stateless `POST /register` compatibility endpoint.

Check a deployment's discovery, annotations, auth challenges, and widget domain:

```sh
python scripts/verify_chatgpt_readiness.py https://mcp.magichour.ai
```

The check exercises both modern and legacy protocols (24 checks when domain
verification is configured). It does not replace the full ChatGPT connection test.

## Test with MCP Inspector

1. Start the server.
2. Run:
   ```sh
   npx @modelcontextprotocol/inspector
   ```
3. In Inspector:
   - Transport: `Streamable HTTP`
   - URL: `http://127.0.0.1:8000/`
   - Header: `Authorization: Bearer <magic_hour_api_key>`
4. Call `ping`.
5. Call `video_assets_generate_presigned_url` or another generated tool.

Notes:

- FastMCP generates endpoint tools from OpenAPI at startup.
- Creation tools return `id` and `credits_charged` immediately.
- OpenAPI `operationId` values are normalized to descriptive snake_case tool names.
- The shared `/v1/files/upload-urls` endpoint is named `video_assets_generate_presigned_url`. It accepts `video`, `audio`, and `image` items.
- Use `wait_for_*_project` to poll jobs. Use `exact_download_urls` exactly as
  returned; never append expiration metadata.
- Image and audio wait tools also return inline media when supported.

Rebuild and type-check the MCP App UI with `cd web && npm ci && npm run build`.

## File uploads

Magic Hour does not accept raw file bytes inside tool arguments. The flow is:

1. Call the generated shared upload-URL tool, `video_assets_generate_presigned_url`
2. Upload the file bytes to the returned `upload_url`
3. Pass the returned `file_path` into the generated creation tool

Direct public media URLs may work, but uploaded `file_path` values are more
reliable. Upload bytes from the caller or a dedicated upload bridge; the hosted
MCP server never reads caller-supplied local filesystem paths. Browser chat needs
a separate upload UI or bridge; see `docs/future-chat-ui-handoff.md`.
