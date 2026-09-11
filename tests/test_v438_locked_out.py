"""
v4.38 - the door that locks with the key inside it.

v4.35 put one session gate in front of every route, and a sign-in is one login
against the configured Management Server. Put a wrong address in and the
consequences compose into a trap:

    every sign-in is tried against that address, so every sign-in fails
    the Settings page, where the address is corrected, is behind the gate
    a saved record overrides .env, so editing .env does not help either

On 2026-09-11 that happened for real - a stored address of `https://x.invalid`
and no way back through the browser at all. The application said only "Could
not reach https://x.invalid", which is true and useless.

Two things close it, and neither weakens the gate:

    the sign-in failure says where the address came from, and distinguishes a
    server that is merely unreachable (wait) from an address that is wrong
    (it will never work, and here is how to clear it)

    tools/reset_credentials.py removes a saved record from outside the
    application, so .env applies again

What is deliberately NOT closed: if the address is right and the server is
down, a new sign-in still cannot succeed - there is nothing to check the
credentials against, and inventing a local password would put a secret at rest
that app/auth.py exists to avoid. An existing session keeps working, because
the cookie is verified locally and never touches the server.
"""

from __future__ import annotations

import io
import contextlib

import pytest
from fastapi.testclient import TestClient

from app import credential_store
from app.config import settings
from app.main import app
from tools import reset_credentials

# TEST-NET-1 (RFC 5737 192.0.2.0/24). The first draft of this file used
# 172.0.2.1 and called it RFC 5737, which it is not - 172.0.0.0/8 is
# ordinary public space, so every one of these tests was opening a TCP
# connection to somebody else's address.
UNREACHABLE = "https://192.0.2.1"


@pytest.fixture
def configured(monkeypatch):
    monkeypatch.setattr(settings, "checkpoint_mgmt", UNREACHABLE)
    monkeypatch.setattr(settings, "checkpoint_user", "admin")
    monkeypatch.setattr(settings, "checkpoint_password", "from-dot-env")
    # The whole suite runs in 20s; five connect attempts to a black hole at
    # the configured 90s each took 106s on their own.
    monkeypatch.setattr(settings, "checkpoint_timeout", 0.25)
    return TestClient(app)


def _detail(client) -> str:
    r = client.post("/api/auth/login", json={"user": "admin", "password": "x"})
    assert r.status_code in (502, 504), r.status_code
    return r.json()["detail"]


class TestTheFailureSaysWhichKindOfFailureItIs:
    def test_it_names_the_address_that_was_tried(self, configured):
        assert UNREACHABLE in _detail(configured)

    def test_an_address_from_dot_env_is_said_to_come_from_dot_env(self, configured):
        detail = _detail(configured)
        assert "comes from .env" in detail
        assert "Correct it in .env and restart." in detail
        assert "reset_credentials" not in detail, (
            "there is no saved record to clear, so pointing at the tool that "
            "clears one sends the reader somewhere that cannot help")

    def test_a_saved_address_is_named_as_overriding_dot_env(self, configured):
        """The part that made it a trap rather than an inconvenience."""
        credential_store.save("checkpoint", {"mgmt": UNREACHABLE, "user": "admin",
                                             "password": "p"})
        detail = _detail(configured)
        assert "the saved credentials, which override .env" in detail, (
            "somebody editing .env would keep being told the same thing and "
            "never learn that the saved record is what is being used")

    def test_a_saved_address_comes_with_the_way_out(self, configured):
        credential_store.save("checkpoint", {"mgmt": UNREACHABLE, "user": "admin",
                                             "password": "p"})
        detail = _detail(configured)
        assert "tools.reset_credentials --clear checkpoint" in detail

    def test_waiting_is_offered_before_anything_destructive(self, configured):
        """Most of the time the server is simply down, and nothing is wrong."""
        detail = _detail(configured)
        assert "temporarily unreachable, waiting is enough" in detail
        assert detail.index("waiting is enough") < detail.index("wrong")


class TestTheWayOutWorks:
    def test_clearing_one_record_leaves_the_other_alone(self):
        credential_store.save("checkpoint", {"mgmt": "https://x.invalid", "user": "a"})
        credential_store.save("gaia", {"enabled": True, "hosts": "192.0.2.7"})

        assert reset_credentials.clear("checkpoint", assume_yes=True) == 0

        assert credential_store.load("checkpoint") is None
        assert credential_store.load("gaia") == {"enabled": True, "hosts": "192.0.2.7"}, (
            "clearing the Check Point record took the Gaia one with it")

    def test_clearing_nothing_is_not_an_error(self):
        assert reset_credentials.clear("checkpoint", assume_yes=True) == 0

    def test_it_refuses_without_confirmation(self, monkeypatch):
        credential_store.save("checkpoint", {"mgmt": "https://x.invalid"})
        monkeypatch.setattr("builtins.input", lambda *_: "no")
        assert reset_credentials.clear("checkpoint", assume_yes=False) == 1
        assert credential_store.load("checkpoint") is not None, (
            "a declined confirmation still deleted the record")

    def test_it_never_prints_a_password(self, monkeypatch):
        secret = "hunter2-do-not-print"
        monkeypatch.setattr(settings, "checkpoint_password", secret)
        monkeypatch.setattr(settings, "gaia_password", secret)
        credential_store.save("checkpoint", {"mgmt": "https://mgmt.example.invalid",
                                             "user": "admin", "password": secret})
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            reset_credentials.show()
        text = out.getvalue()
        assert secret not in text
        assert "characters)" in text, "it should still say whether one is set"

    def test_it_says_which_source_each_value_came_from(self, monkeypatch):
        """The one question somebody in this situation actually has."""
        monkeypatch.setattr(settings, "checkpoint_mgmt", "https://saved.example.invalid")
        monkeypatch.setattr(settings, "checkpoint_user", "admin")
        credential_store.save("checkpoint", {"mgmt": "https://saved.example.invalid",
                                             "user": "admin", "password": "p"})
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            reset_credentials.show()
        assert "overrides .env" in out.getvalue()

    def test_it_prints_only_ascii(self):
        """It is read in a Windows console, where a middot arrives as a box."""
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            reset_credentials.show()
        out.getvalue().encode("ascii")   # raises if anything is not ascii


class TestTheLimitationIsWrittenDownRatherThanHidden:
    def test_the_tool_says_what_it_cannot_fix(self):
        doc = reset_credentials.__doc__ or ""
        assert "WHAT IT DOES NOT FIX" in doc
        assert "unreachable" in doc

    def test_an_existing_session_is_not_affected_by_an_outage(self):
        """The gate reads the cookie locally; it never asks the server.

        This is why "keep me signed in" matters more than it looks: it is the
        difference between an outage being an outage and an outage being a
        lockout.
        """
        import inspect

        from app import main
        source = inspect.getsource(main.require_session)
        assert "auth.read(request.cookies" in source
        assert "await" not in source.split("if (path in PUBLIC_PATHS", 1)[1].split(")", 1)[0]
