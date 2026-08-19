"""
Shared helpers for tests that assert against the application source.

Before v4.13 the entire frontend lived inside `app/main.py` as one 100KB
Python string, so a UI test could simply read that file. The markup, CSS and
JavaScript are now ordinary files under `app/templates/` and `app/static/`,
and the routes are split across `app/api/`.

`app_source()` concatenates every source file the application is built from,
in a stable order, so an assertion of the form "this behaviour exists in the
application" keeps meaning exactly what it meant before - without pinning the
file it happens to live in today. Tests that care about ordering within the
markup still work, because index.html is concatenated as one unit.
"""

from __future__ import annotations

import functools
from pathlib import Path

APP = Path(__file__).resolve().parent.parent / "app"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


@functools.lru_cache(maxsize=1)
def ui_source() -> str:
    """Markup, then CSS, then JavaScript - the served single-page UI."""
    parts = [_read(APP / "templates" / "index.html")]
    parts += [_read(p) for p in sorted((APP / "static" / "css").glob("*.css"))]
    parts += [_read(p) for p in sorted((APP / "static" / "js").glob("*.js"))]
    return "\n".join(parts)


@functools.lru_cache(maxsize=1)
def python_source() -> str:
    """Every Python module under app/, deepest-stable order."""
    return "\n".join(_read(p) for p in sorted(APP.rglob("*.py")))


@functools.lru_cache(maxsize=1)
def app_source() -> str:
    return ui_source() + "\n" + python_source()
