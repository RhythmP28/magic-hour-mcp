# Magic Hour MCP: ChatGPT integration status

Last verified: 2026-09-14. Branch `chatgpt-production` = upstream `main` (6a53df1)
+ cherry-picked upstream PR #63 (76298c1, submission metadata) + 442527c (OAuth
production work) + 0d75e9b (annotations, domain verification, widget domain,
readiness script), plus the follow-up fixes described below. Official repo: github.com/magichourhq/magic-hour-mcp
(maintainer David Hu), deployed on Vercel at https://mcp.magichour.ai/.

## Summary

- The server speaks MCP JSON-RPC at the root path `/` (`/mcp` returns 404) and now implements what ChatGPT's plugin platform expects from an OAuth authorization server: RFC 9207 `iss`, the stable ChatGPT callback, CIMD, sealed access/refresh tokens, scopes.
- Robert's "ChatGPT never scans the tools" blocker was two bugs on his branch, not an OpenAI-side problem; a fixed test deployment completed DCR, OAuth and the scan and listed all 44 tools in a ChatGPT Business workspace.
- Local and test deployments are ready (110 tests; `scripts/verify_chatgpt_readiness.py` 24/24). A private Business-workspace app is ready pending one human re-test of this exact build.
- Public Plugin Directory submission is not ready: it needs Magic Hour account OAuth (Part B), shared authorization-code storage, refresh replay protection and upstream renewal, policy decisions, and the portal prerequisites.
- Users still log in by pasting an API key by default; OpenAI's plugin guidelines forbid that for the public listing.

## Architecture now

Request path:

```
ChatGPT (Business connector or Plugin Directory app)
  |  Streamable HTTP, JSON-RPC POST at "/"
  |  Authorization: Bearer <mhmcp_v1.* sealed token | raw Magic Hour API key>
  v
https://mcp.magichour.ai   (this repo; Vercel runs `app` from main.py -> mcp_magichour.server)
  |  oauth_compat.py    /register /authorize /token /.well-known/oauth-*  (+ /oauth/callback in broker mode)
  |  openapi_auth.py    BearerPassthroughMiddleware: unwraps sealed tokens, forwards the credential
  |  openapi_server.py  37 tools generated from docs/openapi.json + 7 helpers (ping, wait_for_*, fetch_*) = 44
  |  project_result_app.py  MCP App widget (ui://magic-hour/project-result-v1.html), served from /app/*
  v
https://api.magichour.ai   Authorization: Bearer <Magic Hour API key or, in broker mode, user access token>
```

OAuth flow (what this branch implements):

```
ChatGPT                                   mcp.magichour.ai                              Magic Hour
  | GET /.well-known/oauth-protected-resource  ->|  resource, authorization_servers=[issuer]
  | GET /.well-known/oauth-authorization-server ->|  authorization_response_iss_parameter_supported=true
  |                                              |  client_id_metadata_document_supported=true
  |                                              |  scopes_supported=[mcp, offline_access], S256 only
  | GET /authorize?client_id=https://chatgpt.com/oauth/client.json
  |     &redirect_uri=https://chatgpt.com/connector_platform_oauth_redirect
  |     &code_challenge=..&code_challenge_method=S256&scope=..&state=..  ->|
  |                                              |-- GET https://chatgpt.com/oauth/client.json  (CIMD; host
  |                                              |   allowlist, no redirects, 16 KB / 5 s, cached 300 s)
  |   default mode: HTML API-key form, POST /authorize back
  |                                              |-- POST /v1/ai-image-generator {} (key check, 400 = valid) ->
  |   broker mode:  303 to Magic Hour login (PKCE S256, sealed state) ----------------------------------->
  |                                              |<- GET /oauth/callback?code&state ---------------------|
  |                                              |-- POST MAGIC_HOUR_OAUTH_TOKEN_URL (code + verifier) -->
  |<- 303 redirect_uri?code=..&state=..&iss=<issuer> --|   (code held in a process-local store, 300 s)
  | POST /token grant_type=authorization_code&code_verifier&client_id&redirect_uri ->|
  |<- {access_token: mhmcp_v1.., refresh_token: mhmcp_v1.., expires_in: 28800, token_type: Bearer}
  | POST / tools/list, tools/call  (Bearer mhmcp_v1..) ->|  open AES-GCM token, check audience, forward credential
  | POST /token grant_type=refresh_token ->|  new pair; previous refresh token stays valid until its own expiry
```

Without `MCP_OAUTH_TOKEN_SECRET` the server behaves as upstream main does: the raw
Magic Hour API key is returned as the access token and no refresh token is issued.

## What Robert's blocker was and what actually fixed it

Timeline (Aug 25 to Sep 4): fork `robert-nguyenn/magic-hour-mcp`, branch
`chatgpt-integration`, PR #1 in his fork, OpenAI support case 14263640. After ChatGPT
Business called `POST /register` (201) it never called `/authorize`, `/token`,
`initialize` or `tools/list`; the app showed 0 actions and the "Scan Tools" button
seemed to be missing. The handoff concluded the integration was blocked on OpenAI.

Root cause, found today: two server bugs on his branch made every unauthenticated
MCP request return an empty SSE stream, so ChatGPT's automatic scan received nothing
and stopped there.

1. His `replay_body` helper returned `http.disconnect` to the ASGI app, so the
   request body was never delivered.
2. His branch ran fastmcp 4 and assigned `securitySchemes` on a pydantic model that
   has no such field under fastmcp 4, which broke `tools/list`.

Neither bug existed on the upstream base, which pinned `fastmcp>=3.4.0,<4.0`
and never had the replay code. This branch now upgrades to FastMCP 4 with the
auth-metadata and error-handler adaptations described below. After fixing both on a test deployment, ChatGPT completed
DCR -> OAuth (`/authorize`, `/token`) -> scan and showed all 44 tools as actions in
the Business workspace (Review status: development).

Two things that were misread at the time:

- In the Business UI the scan happens automatically on connect and again when you
  press the app's Refresh button. There is no separate "Scan Tools" step there
  anymore. The Scan Tools button lives in OpenAI's Plugin Submission Portal
  (https://platform.openai.com/plugins), which is the public route; plugins land
  in the Plugins Directory shared by ChatGPT and Codex.
- The missing scan was never an OpenAI-side rejection; the support case can be closed.

## What changed on this branch

Commit 442527c (OAuth):

- RFC 9207 issuer identification: metadata advertises
  `authorization_response_iss_parameter_supported`, and every authorization
  redirect response (success and error) carries `iss=<issuer>`. `mcp_magichour/oauth_compat.py`
  (`_authorization_redirect`, `_authorization_error_redirect`).
- Stable ChatGPT callback `https://chatgpt.com/connector_platform_oauth_redirect`
  added to `ALLOWED_REDIRECT_URIS`; the per-connection
  `https://chatgpt.com/connector/oauth/{12 chars}` pattern, the claude.ai callback and
  `http://localhost:8787/callback` remain. `mcp_magichour/oauth_compat.py`.
- Client ID Metadata Documents (CIMD): an `https://` `client_id` is fetched and
  validated instead of registered. Host allowlist defaults to `chatgpt.com` (and
  subdomains); extend with `MCP_OAUTH_CIMD_ALLOWED_HOSTS`. No redirects followed,
  16 KB and 5 s bounds, 300 s cache; the document's `client_id` must equal its URL,
  `redirect_uris` must be https and must contain the requested `redirect_uri`,
  `grant_types` limited to `authorization_code`/`refresh_token`, public-client
  (`none`) auth must be allowed. Metadata advertises
  `client_id_metadata_document_supported`. `mcp_magichour/cimd.py`.
- Sealed tokens when `MCP_OAUTH_TOKEN_SECRET` (>= 32 chars) is set: AES-256-GCM
  tokens `mhmcp_v1.<base64url>` carrying kind, credential, client, audience, scope,
  `iat`/`exp`; access TTL `MCP_OAUTH_ACCESS_TOKEN_TTL` (default 28800 s), refresh
  TTL `MCP_OAUTH_REFRESH_TOKEN_TTL` (default 2592000 s). Self-contained, so any
  instance can verify them. `mcp_magichour/oauth_tokens.py`.
- Bearer unwrapping: `openapi_auth.current_authorization_header()` opens
  `mhmcp_v1.` tokens, rejects expired/foreign/wrong-audience ones (audience checked
  against `MCP_OAUTH_RESOURCE_URL`, falling back to `MCP_OAUTH_ISSUER_URL`) and
  forwards the inner credential; raw API keys still pass through unchanged.
  `mcp_magichour/openapi_auth.py`.
- Refresh grant: `grant_type=refresh_token` rotates the pair, binds `client_id`,
  checks `resource`, and only narrows scope. Offered to DCR/opaque clients whenever
  sealed tokens are on, and to CIMD clients only if their document lists
  `refresh_token`. `mcp_magichour/oauth_compat.py` (`_refresh_access_token`,
  `_client_may_refresh`).
- Scopes: `scopes_supported = [mcp, offline_access]`; requests are validated,
  de-duplicated and echoed in the token response.
- DCR: `POST /register` now returns `client_id_issued_at` and echoes
  `refresh_token` in `grant_types` when requested and sealed tokens are enabled.
- Broker / account-login mode: with `MAGIC_HOUR_OAUTH_AUTHORIZE_URL`,
  `MAGIC_HOUR_OAUTH_TOKEN_URL`, `MAGIC_HOUR_OAUTH_CLIENT_ID` (optional
  `MAGIC_HOUR_OAUTH_CLIENT_SECRET`, `MAGIC_HOUR_OAUTH_SCOPES`,
  `MAGIC_HOUR_OAUTH_CALLBACK_PATH`, default `/oauth/callback`), `GET /authorize`
  303-redirects the user to Magic Hour's login with PKCE S256 and a sealed `state`
  (10 min TTL); `GET /oauth/callback` exchanges the code and mints our tokens; the
  API-key form is disabled (`POST /authorize` returns `invalid_request`). Requires
  `MCP_OAUTH_TOKEN_SECRET` (startup `RuntimeError` otherwise).
  `mcp_magichour/upstream_oauth.py`, `oauth_compat.py` (`upstream_callback`).
- New dependency `cryptography>=42.0` in `pyproject.toml`.

Commit 0d75e9b (ChatGPT submission surface):

- Per-tool annotations instead of a blanket value: 12 tools `readOnlyHint=true`
  (`ping`, `account_retrieve`, the three `*_projects_retrieve_details`,
  `face_detection_retrieve_details`, three `fetch_*_download`, three
  `wait_for_*_project`); 3 `destructiveHint=true` (`video|image|audio_projects_delete`);
  `openWorldHint=false` on all 44. `DIAGNOSTIC_LOGGING_COUNTS_AS_WRITE = False` in
  `mcp_magichour/openapi_policies.py` flips back to PR #63's all-false reading.
  The policy raises on unreviewed routes, but FastMCP catches that exception;
  the tests enforce the reviewed list before deployment (see limitation 9).
  `GET /v1/account` was added to the reviewed read list.
- `chatgpt-app-submission.json` regenerated for all 44 tools with matching hints and
  paste-ready justifications; `docs/chatgpt-tool-annotations.md` documents every
  tool and the decision log; `tests/test_openapi_server.py` keeps code, JSON and doc
  in agreement.
- `GET /.well-known/openai-apps-challenge` serves `OPENAI_APPS_CHALLENGE_TOKEN` as
  `text/plain` with `Cache-Control: no-store`, read per request; 404 `not configured`
  when unset. `mcp_magichour/openapi_server.py`.
- Widget domain: `MCP_APP_WIDGET_DOMAIN` (default `MCP_APP_ORIGIN`) is emitted on
  the result resource as `_meta.ui.domain` and `_meta["openai/widgetDomain"]`.
  `mcp_magichour/project_result_app.py`, `openapi_server.py`.
- `scripts/verify_chatgpt_readiness.py`: credential-free checks of a deployment
  against the ChatGPT plugin requirements (one throwaway DCR registration).
- Tests: `tests/test_oauth_production.py`, `tests/test_upstream_oauth.py`,
  `tests/test_chatgpt_discovery.py` additions; expectations updated for the current
  server instructions and the authorization page's `autocomplete="new-password"`.

Follow-up review fixes:

- Broker login state is bound to a random, host-only, Secure, HttpOnly,
  SameSite=Lax cookie. A callback from another browser fails before any upstream
  token exchange. Success and upstream denial clear the cookie. Broker tests use
  HTTPS; only the latest login started in a browser can complete.
- Refresh scope narrowing is applied to both newly issued tokens. Malformed CIMD
  URLs, non-ASCII token request values, and malformed resource URLs return OAuth
  errors rather than unhandled exceptions. Files: `mcp_magichour/oauth_compat.py`,
  `mcp_magichour/cimd.py`, `tests/test_oauth_production.py`,
  `tests/test_upstream_oauth.py`.
- The readiness script normalizes HTTP header names, so lowercase headers from
  proxies work correctly. `README.md` now includes the configuration and test entry
  points.
- The earlier multi-reviewer workflow was interrupted before any final verdict.
  Its recoverable notes were checked against code and targeted regression tests;
  this document does not claim a completed independent security audit.

Protocol compatibility follow-up:

- ChatGPT later sent `MCP-Protocol-Version: 2026-07-28`. The FastMCP 3/MCP 1
  preview rejected it with HTTP 400. The original 16-check readiness script only
  exercised the legacy protocol and missed this failure.
- `pyproject.toml` now pins FastMCP 4.0.3, MCP 2.2.0, and httpx2 2.13.0. The SDK
  natively supports the modern sessionless protocol and legacy initialization.
  Requests are not relabeled or silently downgraded.
- `oauth_compat.py` places per-tool auth declarations in `_meta.securitySchemes`,
  the supported OpenAI compatibility field, instead of assigning an undeclared
  Pydantic field. `mcp_errors.py` uses SDK v2 handler registration and errors;
  HTTP clients and transports use httpx2 consistently.
- `tests/test_modern_protocol.py` covers modern discovery, all 44 tool descriptors,
  sealed-token ping, image creation and polling with a mock API, widget loading,
  auth challenges, invalid arguments, and rejection of unknown protocol versions.
  The existing legacy tests also pass. The live preview passes 24 checks including
  the modern HTTP headers and per-request metadata envelope.
- The user confirmed ping and account retrieval in ChatGPT before this upgrade.
  Their subsequent generation attempt exposed the protocol mismatch. A human
  image-generation retry is still required after this fix.

References: [FastMCP 4 upgrade guide](https://gofastmcp.com/getting-started/upgrading/from-fastmcp-3),
[modern MCP transport](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http),
and [OpenAI tool metadata](https://developers.openai.com/plugins/reference).

## What works today (verified)

- 102 unit tests pass (`tests/`), covering the token codec, CIMD resolver, issuer
  identification, stable callback, refresh rotation, scope handling, bearer
  unwrapping, broker round trip and failure paths, annotations, submission-file
  agreement, discovery, widget CSP, and the challenge endpoint.
- `scripts/verify_chatgpt_readiness.py <base-url>` reports 24/24 PASS against the
  test deployment: protected-resource and authorization-server metadata, `iss`
  support, CIMD, refresh grant, DCR with the stable callback, challenge token,
  `initialize`, `tools/list` (44 tools, all with the three hints and
  `securitySchemes`), the `mcp/www_authenticate` challenge on an unauthenticated
  `tools/call`, the HTTP 401 `WWW-Authenticate` header, and the widget domain on
  the UI template, plus modern `server/discover`, `tools/list`, tool-level auth
  challenges, and resource listing/reading using `2026-07-28`.
- ChatGPT Business end-to-end (DCR -> `/authorize` -> `/token` -> automatic scan ->
  44 actions) was completed today, but against Robert's fixed branch, which uses
  legacy raw-key tokens and DCR. This branch's CIMD + sealed-token path has been
  exercised in an additional real-ASGI integration test: live fetch of ChatGPT's
  CIMD document, stable callback and `iss`, sealed token exchange, authenticated
  `ping`, refresh, tamper rejection, DCR fallback, and raw-key compatibility. That
  test used a stub Magic Hour API, not a real ChatGPT user or production credentials.
- Raw API-key bearer compatibility passes local tests. Separate human checks in
  Claude, Claude Code, Codex CLI and MCP Inspector were not repeated for this build.

## What remains outside this repo: Part B, Magic Hour account OAuth

The public plugin cannot ask users to paste an API key. Broker mode in
`mcp_magichour/upstream_oauth.py` is ready to use Magic Hour's own authorization
server as soon as it exists. Magic Hour's platform has to provide:

Required

1. An OAuth 2.1 authorization-code endpoint with PKCE S256 where a user logs in and
   consents, and a token endpoint. The MCP server sends
   `response_type=code`, `client_id`, `redirect_uri`, `state`, `code_challenge`,
   `code_challenge_method=S256` and, if `MAGIC_HOUR_OAUTH_SCOPES` is set, `scope`.
   `state` is an opaque sealed blob whose size depends on the client request and
   must be returned unchanged. The browser must preserve the login cookie.
2. A registered client for the MCP server, public with PKCE or confidential with a
   client secret (sent as HTTP Basic on the token request), whose redirect URI is
   `<issuer>/oauth/callback`, i.e. `https://mcp.magichour.ai/oauth/callback` in
   production (`MAGIC_HOUR_OAUTH_CALLBACK_PATH` changes the path).
3. Token endpoint behaviour the broker accepts: `application/x-www-form-urlencoded`
   request with `grant_type=authorization_code`, `code`, `redirect_uri`, `client_id`,
   `code_verifier`; `200` JSON response with a non-empty `access_token` string
   (<= 4096 chars, no whitespace) and `token_type` `bearer` (or omitted). Any other
   status is reported to ChatGPT as `access_denied`.
4. Magic Hour API acceptance of those user access tokens as
   `Authorization: Bearer <token>` on every endpoint the 44 tools call, exactly like
   API keys today.

Recommended

- Token introspection, or short upstream TTLs, so a revoked Magic Hour session stops
  working at the API. The MCP server cannot revoke sealed tokens itself.
- A revocation story for the MCP client: rotating `MCP_OAUTH_TOKEN_SECRET`
  invalidates every outstanding token at once; anything finer needs a shared store.
- Upstream token lifetime: the broker seals the upstream access token as the
  credential and each MCP refresh re-seals that same credential. It never renews
  the upstream token or reads its expiry. Before launch, agree the backend refresh
  contract and extend the broker to renew upstream credentials, or require
  reauthorization when they expire. A long upstream TTL alone does not solve this:
  repeated MCP refresh currently extends the session indefinitely.
- Confirm Magic Hour's authorization page renders inside the ChatGPT OAuth popup and
  returns to `/oauth/callback` with `error=access_denied` on cancel (the broker
  turns a missing `code` or any `error` into an OAuth error redirect to ChatGPT).

## Deploy (Vercel)

1. Vercel serves `app` from `main.py`; the build script in `pyproject.toml`
   (`[tool.vercel.scripts]`) runs `npm --prefix web ci && npm --prefix web run build`
   to produce the widget in `mcp_magichour/static/project-result/`.
2. Dependencies come from `pyproject.toml`: `fastmcp==4.0.3`, `mcp==2.2.0`,
   and `httpx2==2.13.0` are tested together. These replace the earlier FastMCP 3 pin
   because ChatGPT sends MCP `2026-07-28`. There is no Python lockfile upstream;
   add one (`pip-compile` to `requirements.txt` or `uv lock`) and point Vercel at it
   so a resolver change cannot alter production.
3. Environment variables (Vercel > Project > Settings > Environment Variables):

| Variable | Required? | Default | Purpose |
|---|---|---|---|
| `MCP_OAUTH_ISSUER_URL` | Yes in production | request base URL | OAuth issuer in metadata, the `iss` parameter, and the base of `/oauth/callback`. Set to `https://mcp.magichour.ai`. |
| `MCP_OAUTH_RESOURCE_URL` | Yes in production | issuer | Protected-resource identifier and sealed-token audience. Set to `https://mcp.magichour.ai`. |
| `MCP_OAUTH_TOKEN_SECRET` | Yes for ChatGPT (sealed tokens, refresh, broker mode) | unset = legacy raw-key tokens | >= 32 random chars; AES key = SHA-256 of it. Rotating it logs every user out. |
| `MCP_OAUTH_ACCESS_TOKEN_TTL` | No | `28800` | Access token lifetime in seconds. |
| `MCP_OAUTH_REFRESH_TOKEN_TTL` | No | `2592000` | Refresh token lifetime in seconds; old refresh tokens stay valid this long after rotation. |
| `MCP_OAUTH_CIMD_ALLOWED_HOSTS` | No | `chatgpt.com` always included | Comma-separated extra hosts whose CIMD documents may be used as `client_id`. |
| `UPSTASH_REDIS_REST_URL` + `UPSTASH_REDIS_REST_TOKEN` | Yes for multi-instance deployments | unset = process-local code store | Upstash-style Redis REST endpoint for the shared authorization-code store (Vercel KV's `KV_REST_API_URL`/`KV_REST_API_TOKEN` also work). Needs `MCP_OAUTH_TOKEN_SECRET`; payloads are AES-GCM sealed and codes are single-use via `GETDEL`. |
| `MAGIC_HOUR_API_BASE_URL` | No | `https://api.magichour.ai` | Upstream API for tools and API-key validation. |
| `MAGIC_HOUR_OAUTH_VALIDATION_PATH` | No | `/v1/ai-image-generator` | Endpoint POSTed with `{}` to validate a pasted API key (400 = valid). |
| `MAGIC_HOUR_OPENAPI_PATH` | No | `docs/openapi.json` | Spec the tools are generated from. |
| `MAGIC_HOUR_OAUTH_AUTHORIZE_URL` | Part B only | unset | Magic Hour authorization endpoint (https). Setting any `MAGIC_HOUR_OAUTH_*` URL/client var enables broker mode and validates all three. |
| `MAGIC_HOUR_OAUTH_TOKEN_URL` | Part B only | unset | Magic Hour token endpoint (https). |
| `MAGIC_HOUR_OAUTH_CLIENT_ID` | Part B only | unset | Client registered for this server at Magic Hour. |
| `MAGIC_HOUR_OAUTH_CLIENT_SECRET` | No | unset | Sent as HTTP Basic on the token exchange when set. |
| `MAGIC_HOUR_OAUTH_SCOPES` | No | empty (omitted) | `scope` requested from Magic Hour. |
| `MAGIC_HOUR_OAUTH_CALLBACK_PATH` | No | `/oauth/callback` | Path Magic Hour redirects back to; must match the registered redirect URI. |
| `OPENAI_APPS_CHALLENGE_TOKEN` | For portal domain verification | unset (endpoint returns 404) | Body of `GET /.well-known/openai-apps-challenge`. Read per request; Vercel environment changes require a new deployment. |
| `MCP_APP_ORIGIN` | Yes in production | `https://$VERCEL_URL`, else `https://mcp.magichour.ai` | Origin of widget assets and CSP `connect-src`/`script-src`. Set explicitly: on Vercel `VERCEL_URL` is the `*.vercel.app` deployment host, not the custom domain. |
| `MCP_APP_WIDGET_DOMAIN` | No | `MCP_APP_ORIGIN` | Emitted as `_meta.ui.domain` and `openai/widgetDomain` on the result template. |
| `POSTHOG_PROJECT_TOKEN` | No | unset = analytics disabled | PostHog project token for OAuth/tool events. |
| `POSTHOG_HOST` | No | `https://us.i.posthog.com` | PostHog ingestion host. |
| `DEBUG` / `ENVIRONMENT` | No | unset | `DEBUG=true` or `ENVIRONMENT=development|dev` makes a missing PostHog token a startup error. |

   `MAGIC_HOUR_API_KEY` in `.env.example` is not read by the server.

4. Run the tests before deploying (the two widget tests need the web build):

   ```sh
   pip install -e .
   (cd web && npm ci && npm run build)
   python -m unittest discover -s tests -q  # expect 102 tests, OK
   ```

5. Deploy, then verify the live deployment without credentials:

   ```sh
   python scripts/verify_chatgpt_readiness.py https://mcp.magichour.ai
   ```

   Expect 22 PASS, 0 FAIL. `openai-apps-challenge not configured` is a WARN until
   `OPENAI_APPS_CHALLENGE_TOKEN` is set. The script exits 1 on any FAIL.

6. Do not enable `MAGIC_HOUR_OAUTH_*` until Part B exists; with them set and the
   upstream endpoints missing, every ChatGPT login redirects to a dead URL.

## How to test the full ChatGPT flow (Business workspace)

Ping and account retrieval were confirmed by the user before the protocol upgrade.
Repeat the flow and complete image generation against this new build.

1. Deploy this branch with `MCP_OAUTH_ISSUER_URL`, `MCP_OAUTH_RESOURCE_URL`,
   `MCP_OAUTH_TOKEN_SECRET`, `MCP_APP_ORIGIN` set. Run the readiness script (24/24).
2. In ChatGPT (Business workspace, admin): Settings > Apps & Connectors (or the
   workspace admin's Connectors page) > Create / Add app > MCP server URL
   `https://mcp.magichour.ai/` (with the trailing slash, root path), authentication
   OAuth. Leave client id/secret empty; ChatGPT uses CIMD or DCR.
3. Connect. In private test mode, expect the Magic Hour API-key page. In broker
   mode, expect Magic Hour account login and consent, then `/oauth/callback`.
   Both flows redirect back to
   `https://chatgpt.com/connector_platform_oauth_redirect?code=..&state=..&iss=https://mcp.magichour.ai`.
4. ChatGPT scans automatically after connecting. The app should list 44 actions with
   Review status: development. Press Refresh on the app to re-scan after deploys.
5. In a chat, enable the app and ask for `ping` (expect `pong`), then
   `account_retrieve` (proves the sealed token was unwrapped and accepted by the API),
   then one cheap generation followed by its `wait_for_*_project` to see the widget.
6. Leave the connection for more than 8 hours (or set `MCP_OAUTH_ACCESS_TOKEN_TTL=120`
   on a test deployment) and call a tool again: ChatGPT must silently use the refresh
   grant instead of prompting to reconnect.

What the server side should show, in order:

- `GET /.well-known/oauth-protected-resource`, `GET /.well-known/oauth-authorization-server`.
- Either `GET https://chatgpt.com/oauth/client.json` fetched by the server (CIMD; you
  see `client_id=https://chatgpt.com/oauth/client.json` on the authorize request) or
  `POST /register` 201 (DCR fallback; random `client_id`). Both are acceptable.
- `GET /authorize?...&redirect_uri=https://chatgpt.com/connector_platform_oauth_redirect&code_challenge_method=S256&scope=...`
  then `POST /authorize` (form submit) answered with `303` whose `Location` contains
  `code`, `state` and `iss`.
- `POST /token` 200 with `grant_type=authorization_code`; later `POST /token` with
  `grant_type=refresh_token` and no preceding `/authorize`.
- `POST /` for `initialize` (legacy) or `server/discover` (modern), `tools/list`,
  `resources/list`, then `tools/call` with
  `auth_scheme=bearer`.

How to read the logs:

- Application log lines (Python loggers `uvicorn.error.mcp_auth`, `.mcp_oauth`,
  `.mcp_tools`): `request_started request_id=.. method=.. path=.. auth_present=..
  auth_scheme=..` / `request_completed .. status=.. latency_ms=..` for every request
  (path only, no query string, never the token); `registration_rejected`,
  `cimd_rejected reason=..`, `token_rejected reason=..` (`code_invalid_or_expired`,
  `client_mismatch`, `redirect_uri_mismatch`, `resource_mismatch`, `pkce_failed`,
  `refresh_token_invalid`, `scope_exceeded`), `auth_rejected reason=..`
  (`missing`, `malformed`, `sealed_token_invalid`, `audience_mismatch`,
  `sealed_token_disabled`), and `tool_call_started name=.. arguments=<redacted>`.
- On Vercel: Project > Logs (runtime logs), filter by path. INFO-level lines depend on
  the runtime's log level; WARNING-level rejections always show. Query-string
  parameters (`client_id`, `redirect_uri`) are visible in Vercel's request log for
  `GET /authorize`, not in the application lines.
- Locally or on a uvicorn test box (`uvicorn mcp_magichour.server:app --lifespan on
  --proxy-headers`), uvicorn's access log prints the full request line including the
  `client_id` and `redirect_uri` query parameters.
- PostHog (when configured): `oauth_authorization_code_issued`,
  `oauth_connection_completed`, `oauth_authorization_code_lookup_missed`
  (carries `code_store_id`; a different id from the issue event means `/authorize`
  and `/token` hit different instances), `oauth_request_failed` with
  `stage`/`reason`/`http_status`.
- The `iss` parameter is not logged by the app; confirm it from the browser's network
  tab on the `303` from `POST /authorize`, or with `curl -i` in a scripted test.

## How to submit through OpenAI (Plugin Submission Portal)

Source requirements: [submission workflow](https://developers.openai.com/plugins/deploy/submission),
[portal validation rules](https://developers.openai.com/plugins/deploy/submission-errors),
[plugin guidelines](https://developers.openai.com/plugins/app-guidelines), and
[OAuth integration](https://developers.openai.com/plugins/build/auth), checked 2026-09-14.

Prerequisites checklist (all outside this repo unless noted):

- [ ] Part B live and `MAGIC_HOUR_OAUTH_*` set, so the login is Magic Hour's own page,
      not the API-key form (OpenAI's guidelines forbid collecting API keys).
- [x] Shared authorization-code store implemented in this repo (`oauth_code_store.py`,
      supersedes upstream draft PR #86). Still to do at deploy time: provision Upstash
      Redis (or Vercel KV) and set `UPSTASH_REDIS_REST_URL`/`UPSTASH_REDIS_REST_TOKEN`.
- [ ] Verified Magic Hour organization on https://platform.openai.com with Apps
      Management write permission for the person submitting. Do not submit under a
      personal or unrelated organization.
- [ ] Public website URL, support URL, privacy policy URL, terms of service URL.
- [ ] Logo, screenshots 706 px wide, a demo recording of the flows.
- [ ] Reviewer demo credentials: a Magic Hour account with credits the reviewer can
      log in with (broker mode), without MFA, email/SMS confirmation, or private
      network access, and stable, consenting or synthetic media fixtures for
      the upload-based test cases.
- [ ] The 5 positive and 3 negative test cases in `chatgpt-app-submission.json`
      re-run against production, with job ids, `credits_charged`, terminal status and
      downloadable output recorded.
- [ ] Policy decisions in "Known limitations & risks" made and, where needed, tools
      removed or gated.

Portal steps, in order:

1. Open https://platform.openai.com/plugins under the Magic Hour organization and
   create a new plugin draft of type "With MCP". Inspect existing drafts first.
2. Server URL: `https://mcp.magichour.ai/` (Universal). Authentication: OAuth; the
   portal discovers the metadata itself.
3. Verify Domain: the portal shows a token; put it in `OPENAI_APPS_CHALLENGE_TOKEN`
   on Vercel, redeploy for the environment change to take effect, and confirm
   `curl https://mcp.magichour.ai/.well-known/openai-apps-challenge` returns the
   token as `text/plain`, then click Verify.
4. Scan Tools. Expect 44 tools, no `annotations_required` errors, no "Widget domain
   is not set" warning. If a tool shows a missing hint, the deployment is stale.
5. App Info: copy `app_info` from `chatgpt-app-submission.json` (display name
   "Magic Hour", subtitle, description, category DESIGN). If the form offers a JSON
   import, import the whole file instead of typing.
6. Per-tool justifications (the `justification_required` fields): for each tool paste
   the three cells from the table in `docs/chatgpt-tool-annotations.md`
   (readOnlyHint / openWorldHint / destructiveHint justification). They are the same
   strings as `tools.<name>.justifications.{read_only,open_world,destructive}_justification`
   in `chatgpt-app-submission.json`. The decision log in that document is the answer
   if a reviewer asks why status polls are read-only despite request logging.
7. Testing: enter the 5 positive and 3 negative cases from the JSON, reviewer
   credentials, and the demo recording; attach screenshots and logo.
8. Policy attestations and release notes, then Submit for Review. Claim "submitted"
   only after the portal confirms; publication to the Plugins Directory is a separate
   action after approval.

## Readiness levels

| Level | Verdict | What is missing |
|---|---|---|
| Local / test deployment | Ready | Nothing: 110 tests pass, readiness script 24/24. |
| ChatGPT private app (Business workspace) | Ready, pending one human re-test against this build | Run the flow above once with CIMD + sealed tokens; ping/account worked in ChatGPT before the protocol upgrade; the upgraded build passes the scripted flow with a mock API, and needs a human generation retry. |
| Public Plugin Directory submission | Not ready | Part B (account OAuth), shared code storage, refresh replay protection and upstream renewal, policy decisions, portal prerequisites (verified org, public URLs, reviewer credentials, 5/3 test cases, recording, logo, 706 px screenshots). |

## Known limitations & risks

1. Resolved when Redis is configured: the authorization-code store defaults to
   process-local (`AuthorizationCodeStore` in `oauth_code_store.py`, a dict with a
   300 s TTL), which on multi-instance Vercel returns `invalid_grant`
   intermittently when `/authorize` and `/token` land on different instances
   (PostHog `oauth_authorization_code_lookup_missed` with a different
   `code_store_id` is the signature). Setting `UPSTASH_REDIS_REST_URL` +
   `UPSTASH_REDIS_REST_TOKEN` (or Vercel KV's `KV_REST_API_URL`/`KV_REST_API_TOKEN`)
   switches to `RedisAuthorizationCodeStore`: codes are keyed by SHA-256, sealed
   with AES-GCM derived from `MCP_OAUTH_TOKEN_SECRET`, expired by Redis TTL, and
   consumed atomically with `GETDEL` (single use across instances; covered by
   `tests/test_oauth_code_store.py`, including a cross-instance token exchange).
   Provision an Upstash Redis database and set both variables before public launch.
   Sealed tokens themselves are stateless and unaffected.
2. Refresh tokens rotate but are not revoked: the previous refresh token stays valid
   until its own `exp` (30 days by default). Every refresh starts another TTL, so
   continuous refresh can extend a session indefinitely. A shorter TTL limits
   idle exposure but does not provide replay detection or revocation. Implement
   shared token-family rotation/reuse detection or sender-constrained refresh
   tokens before public launch.
3. The API-key paste form is the default login UX until Part B exists and the
   `MAGIC_HOUR_OAUTH_*` variables are set. OpenAI's plugin guidelines forbid
   collecting API keys, so the public submission must not go out in this mode. Retained for
   private development testing.
4. No dependency lockfile upstream; `pip install -e .` resolves fresh on every build.
   Add one.
5. Policy review risks for the public directory:
   - `ai_voice_generator_create_audio` exposes a `voice_name` enum of 1,267 presets
     in the current `docs/openapi.json` (synced daily, so the count moves), including
     named real people (Elon Musk, Barack Obama, Morgan Freeman, Taylor Swift, ...).
   - `ai_voice_cloner_create_audio` (voice cloning), `face_swap_create_video`,
     `face_swap_photo_create_image`, `head_swap_create_image`, `body_swap_create_image`,
     `lip_sync_create_video`, `ai_talking_photo_create_talking_photo`,
     `character_replace_create_video` touch OpenAI's usage policies on likeness
     without consent. Decide per tool whether to keep, gate, or hide before submitting.
   - Commerce rule: tool output and the widget must not link to buying credits or
     upgrading. As of this branch no server-authored text or widget code contains such
     links (the widget only displays `credits_charged`); Magic Hour API error bodies
     pass through unmodified, so check that tier-restriction errors from the API do
     not carry upgrade links.
6. Human ChatGPT ping/account calls succeeded before the protocol upgrade, but
   image generation and token refresh still need human verification on this build.
7. Broker mode never refreshes upstream or honors upstream expiry. Implement renewal
   or explicit reauthorization against the agreed backend contract (see Part B).
8. `MCP_APP_ORIGIN` defaults to the `VERCEL_URL` deployment host; leaving it unset in
   production points the widget CSP at a `*.vercel.app` origin.
9. fastmcp catches exceptions from `mcp_component_fn`, so the fail-closed check in
   `customize_openapi_component` does not remove an unreviewed tool at runtime;
   `test_every_exposed_tool_has_explicit_submission_hints` is the check that fails
   the build when the daily OpenAPI sync adds a route. Keep that test in deployment checks.
10. CIMD fetches have per-request time and size bounds, but no global request rate
    limit or negative cache. Configure edge rate limits for OAuth endpoints before
    public exposure and load-test uncached metadata requests.
11. `mcp` is a coarse access scope; it does not distinguish individual tools.
    Magic Hour must enforce user permissions and consent at its API.

## Outdated documents

- `docs/chatgpt-app-submission-review.md` (dated 2026-09-07): still describes all
  `readOnlyHint=false`, 43 tools, and production without annotations. Superseded by
  `docs/chatgpt-tool-annotations.md` (44 tools, 12 read-only, 3 destructive) and this
  file. Its test-case observations and remaining-gates list are still useful history.
- Robert's `integration-handoff.md` in his fork (`robert-nguyenn/magic-hour-mcp`,
  branch `chatgpt-integration`) says the integration is blocked on OpenAI support.
  No longer true; see "What Robert's blocker was". The `integration-handoff.md` in
  this repo is upstream's FastAPI mount checklist, a different document; its "Auth
  model" section predates sealed tokens (the inbound bearer may now be an `mhmcp_v1.`
  token that `openapi_auth.py` unwraps before the API call).
- `docs/future-oauth-support.md`: says the shim "does not mint refresh tokens", that
  the API key is the access token, and "run one worker". True only when
  `MCP_OAUTH_TOKEN_SECRET` is unset; codes are still process-local (limitation 1).
- `user.md` "Connect with Claude": says the server does not support dynamic client
  registration and requires OAuth Client ID `magic-hour-mcp`. `POST /register` exists
  (upstream), so the manual client id is no longer required.
- `README.md` "OAuth compatibility" was updated in this branch to mention sealed
  tokens, broker mode and the readiness script; `.env.example` does not list the new
  variables (see the table above).
