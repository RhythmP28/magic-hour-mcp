import os
from html import escape
from pathlib import Path

MCP_APP_VIEW_URI = "ui://magic-hour/project-result-v1.html"
MCP_APP_VIEW_PATH = "/app/project-result"
MCP_APP_ASSET_PATH = "/app/project-result-assets"
MCP_APP_SERVER_ORIGIN = "https://mcp.magichour.ai"
# Deployment-specific VERCEL_URL hosts can sit behind Vercel deployment
# protection; prefer the always-public production domain when defaulting.
MCP_APP_ORIGIN = os.getenv(
    "MCP_APP_ORIGIN",
    f"https://{os.getenv('VERCEL_PROJECT_PRODUCTION_URL') or os.getenv('VERCEL_URL', 'mcp.magichour.ai')}",
).rstrip("/")
# Origin that hosts the widget iframe. Emitted as `_meta.ui.domain` (MCP Apps)
# and `_meta["openai/widgetDomain"]` (ChatGPT Apps SDK) on the result resource.
MCP_APP_WIDGET_DOMAIN = os.getenv("MCP_APP_WIDGET_DOMAIN", MCP_APP_ORIGIN).rstrip("/")
MCP_APP_MEDIA_ORIGIN = "https://videos.magichour.ai"
# Magic Hour serves signed downloads from first-party subdomains; accept any of
# them so image/audio CDNs other than videos.* keep inline media and the widget
# preview working.
MCP_APP_MEDIA_HOST_SUFFIX = "magichour.ai"
MCP_APP_MEDIA_ORIGIN_WILDCARD = f"https://*.{MCP_APP_MEDIA_HOST_SUFFIX}"


def is_allowed_media_host(hostname: str | None) -> bool:
    return hostname is not None and (
        hostname == MCP_APP_MEDIA_HOST_SUFFIX
        or hostname.endswith("." + MCP_APP_MEDIA_HOST_SUFFIX)
    )
MCP_APP_DIST_PATH = Path(__file__).with_name("static") / "project-result"
MCP_APP_MIME_TYPE = "text/html;profile=mcp-app"
_MCP_APP_CSP_PLACEHOLDER = "__MCP_APP_CSP__"
MCP_APP_VIEW_CSP = (
    "default-src 'none'; "
    f"connect-src {MCP_APP_SERVER_ORIGIN} {MCP_APP_ORIGIN}; "
    "frame-ancestors https://chatgpt.com https://claude.ai; "
    "form-action 'none'; "
    f"img-src {MCP_APP_MEDIA_ORIGIN} {MCP_APP_MEDIA_ORIGIN_WILDCARD}; "
    f"media-src {MCP_APP_MEDIA_ORIGIN} {MCP_APP_MEDIA_ORIGIN_WILDCARD}; "
    f"script-src {MCP_APP_ORIGIN}; "
    f"style-src {MCP_APP_ORIGIN}; "
    "base-uri 'none'"
)


def read_mcp_app_html() -> str:
    try:
        app_html = (MCP_APP_DIST_PATH / "index.html").read_text(encoding="utf-8")
    except FileNotFoundError:
        raise RuntimeError("MCP App frontend is missing; run `npm --prefix web run build`.") from None
    return app_html.replace(
        _MCP_APP_CSP_PLACEHOLDER,
        escape(MCP_APP_VIEW_CSP, quote=False).replace('"', "&quot;"),
    )
