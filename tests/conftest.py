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

from app import credential_store  # noqa: E402


@pytest.fixture(autouse=True)
def never_the_operator_s_credential_file(tmp_path, monkeypatch):
    """No test may read or write the real credentials.enc.

    Written after a probe did exactly that. While debugging v4.38 a throwaway
    test POSTed to /api/credentials without the temp-file fixture that the
    credential tests use, and the endpoint did what it is supposed to do: it
    encrypted the probe's placeholder values over the operator's saved
    Management Server address and password. The file is gitignored, so there
    was nothing to restore it from.

    Each credential test pointing the store at its own tmp_path was never
    enough, because it depends on every future test remembering to. This does
    it for all of them, including the ones nobody has written yet.

    Tests that want a store keep declaring their own fixture; theirs runs
    after this one and simply points at a different temporary path.
    """
    monkeypatch.setattr(credential_store, "KEY_FILE", tmp_path / ".credential_key")
    monkeypatch.setattr(credential_store, "ENC_FILE", tmp_path / "credentials.enc")
    # v4.39: the alert destinations file is the operator's too, for the same
    # reason - a test that saves a destination must not replace theirs.
    from app.jobs import alerts
    monkeypatch.setattr(alerts, "CONFIG_FILE", tmp_path / "alerts.json")


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


def settled(client, response):
    """
    The finished answer of a route that may run in the background.

    After v4.39 the long routes (analysis, trace, snapshot, compliance) return
    `{"background": true, "rid": ...}` at once and put their answer on
    /api/progress, so a slow Management Server no longer holds a request open.
    Tests written against the old contract read the answer from the response
    body. This reads it from where it now is, and fails loudly if the job did
    not finish or finished with an error - a test must not pass on a pending
    job.
    """
    body = response.json()
    if not (isinstance(body, dict) and body.get("background") and body.get("rid")):
        return body
    state = client.get("/api/progress", params={"rid": body["rid"]}).json()
    assert state.get("done") is True, f"background job did not finish: {state}"
    assert not state.get("error"), f"background job failed: {state.get('error')}"
    return state.get("result")
