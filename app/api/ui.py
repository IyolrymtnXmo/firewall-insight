"""Serves the single-page UI.

The markup, CSS and JavaScript used to live inside main.py as one 100KB Python
string, which meant no syntax highlighting, no linting, no browser caching and
a 2,473-line module. They are now ordinary files under templates/ and static/.

That move introduced a problem it also has to solve: while the assets were
inline, every reload picked up the newest CSS and JS automatically. As separate
files the browser caches them, so an upgrade can leave a user running new
markup against stale styles - which looks like a broken UI, not a stale cache.
Asset URLs therefore carry a version stamp.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

from ..version import APP_VERSION

router = APIRouter()

APP_DIR = Path(__file__).resolve().parent.parent
TEMPLATE = APP_DIR / "templates" / "index.html"
STATIC = APP_DIR / "static"


def asset_version() -> str:
    """
    Release version plus the newest static mtime.

    The version alone would be correct for releases but useless during
    development, where `uvicorn --reload` restarts Python while the browser
    keeps serving yesterday's CSS. The mtime makes an edit visible on the next
    reload; the version makes an upgrade visible to every existing user.
    """
    try:
        newest = max(p.stat().st_mtime for p in STATIC.rglob("*") if p.is_file())
    except ValueError:
        return APP_VERSION
    return f"{APP_VERSION}-{int(newest)}"


@router.get("/", response_class=HTMLResponse)
async def index():
    # Read per request so `--reload` picks up template edits without a restart.
    html = TEMPLATE.read_text(encoding="utf-8")
    stamp = asset_version()
    return html.replace("/static/css/app.css", f"/static/css/app.css?v={stamp}") \
               .replace("/static/js/app.js", f"/static/js/app.js?v={stamp}")