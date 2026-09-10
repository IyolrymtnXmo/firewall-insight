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
import re
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
def ui_text() -> str:
    """`ui_source()` with every run of whitespace collapsed to one space.

    An HTML formatter is allowed to rewrap a long line. When one ran over
    index.html in commit a5db12b it turned

        >&#9642; Access Policy</button>
    into
        >&#9642; Access
          Policy</button>

    which broke five assertions that were about the *words on the button*,
    not about where the line happened to break. Assertions on visible text
    use this; assertions on structure (ids, attributes, CSS, JS) keep using
    ui_source(), where exact characters really are the contract.
    """
    return re.sub(r"\s+", " ", ui_source())


@functools.lru_cache(maxsize=1)
def python_source() -> str:
    """Every Python module under app/, deepest-stable order."""
    return "\n".join(_read(p) for p in sorted(APP.rglob("*.py")))


@functools.lru_cache(maxsize=1)
def app_source() -> str:
    return ui_source() + "\n" + python_source()


# ---- the suite runs as somebody who is signed in ---------------------------

import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def signed_in(request, monkeypatch):
    """Every test runs with a valid session unless it says otherwise.

    v4.35 closed RISK-01 by putting one session gate in front of every route.
    Without this fixture, every test that touches the API would be asserting
    against a 401 rather than against the thing it is about - and the failure
    would say nothing useful.

    The gate is not disabled. `auth.read` is made to return a username, which
    is precisely what a valid signed cookie does, so the middleware runs and
    the route runs. The gate's own behaviour - refusing anonymous callers,
    which paths are public, rate limiting, setup mode - is tested in
    test_v435_auth.py, whose tests opt out with `@pytest.mark.anonymous`.
    """
    if "anonymous" in request.keywords:
        return
    monkeypatch.setattr("app.auth.read", lambda token: "test-operator")
