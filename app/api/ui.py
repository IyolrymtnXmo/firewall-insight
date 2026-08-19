"""Serves the single-page UI.

The markup, CSS and JavaScript used to live inside main.py as one 100KB
Python string, which meant no syntax highlighting, no linting, no browser
caching and a 2,473-line module. They are now ordinary files under
templates/ and static/.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter()

TEMPLATE = Path(__file__).resolve().parent.parent / "templates" / "index.html"


@router.get("/", response_class=HTMLResponse)
async def index():
    # Read per request so `uvicorn --reload` picks up template edits without
    # a restart. The file is small and the OS page cache makes this cheap.
    return TEMPLATE.read_text(encoding="utf-8")
