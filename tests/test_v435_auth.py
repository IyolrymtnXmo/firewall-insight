"""
v4.35 - RISK-01 closed. Who is allowed to use this application.

Every test here opts out of the `signed_in` fixture, because the gate is the
thing under test. Everything else in the suite runs with a session, which is
why those tests assert against their own subject rather than against a 401.

What has to hold:

    anonymous callers get nothing        not a partial page, not an empty list
    the public list is small and fixed   `/` is on it so a browser has
                                         somewhere to sign in; nothing that
                                         returns policy is
    a password is never stored           the whole reason sign-in borrows the
                                         Check Point credentials
    this cannot lock an admin out        failed attempts are refused here
                                         rather than forwarded
    setup mode is stated, not silent     with nothing configured there is
                                         nobody to check against, and the
                                         application says so
"""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from app import auth
from app.config import settings
from app.main import app

pytestmark = pytest.mark.anonymous


@pytest.fixture
def configured(monkeypatch, tmp_path):
    """Credentials exist, so sign-in is required and can be checked."""
    monkeypatch.setattr(auth, "KEY_FILE", tmp_path / ".session_key")
    monkeypatch.setattr(settings, "checkpoint_mgmt", "https://mgmt.example.invalid")
    monkeypatch.setattr(settings, "checkpoint_user", "admin")
    monkeypatch.setattr(auth, "attempts", auth._Attempts())
    return TestClient(app)


@pytest.fixture
def unconfigured(monkeypatch, tmp_path):
    monkeypatch.setattr(auth, "KEY_FILE", tmp_path / ".session_key")
    monkeypatch.setattr(settings, "checkpoint_mgmt", "")
    monkeypatch.setattr(settings, "checkpoint_user", "")
    return TestClient(app)


class TestAnonymousCallersGetNothing:
    @pytest.mark.parametrize("path", [
        "/api/bootstrap", "/api/runs", "/api/schedules", "/api/snapshots",
        "/api/credentials/status", "/api/compliance-profiles",
        "/api/package-analyze?package=P", "/api/health-baselines",
    ])
    def test_a_data_route_is_refused(self, configured, path):
        r = configured.get(path)
        assert r.status_code == 401, f"{path} answered {r.status_code} anonymously"
        assert "Sign in" in r.json()["detail"]

    def test_a_mutating_route_is_refused(self, configured):
        assert configured.post("/api/runs?package=P").status_code == 401
        assert configured.put("/api/schedules", json={"package": "P", "at": "09:00"}
                              ).status_code == 401
        assert configured.post("/api/credentials", json={"type": "checkpoint"}
                               ).status_code == 401

    def test_the_refusal_carries_no_data(self, configured):
        body = configured.get("/api/runs").json()
        assert set(body) == {"detail"}, body


class TestThePublicListIsSmallAndDeliberate:
    def test_the_page_itself_is_reachable(self, configured):
        """Refusing it would leave a browser with nowhere to sign in."""
        assert configured.get("/").status_code == 200

    def test_the_page_carries_no_policy(self, configured):
        """The shell is public. What fills it is not.

        Two real values had been shipped inside it: a lab package name in a
        placeholder I added in v4.34, and the lab's actual gateway addresses in
        the Gaia placeholder, there since v4.30. Neither was policy the
        application had fetched - both were typed into the template - which is
        exactly how this kind of thing survives review.

        Addresses in 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24 are
        reserved by RFC 5737 for documentation and can never belong to anyone.
        """
        import re
        html = configured.get("/").text

        found = set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", html))
        allowed_prefixes = ("192.0.2.", "198.51.100.", "203.0.113.",
                            "127.0.0.", "0.0.0.0", "255.255.255.")
        real = {ip for ip in found
                if not any(ip.startswith(pre) for pre in allowed_prefixes)}
        assert not real, (
            f"the public page ships real addresses: {sorted(real)}. Use an "
            "RFC 5737 documentation address in a placeholder.")

        for leak in ("Cleanup rule", "Lab-Outbound", "Admin-Access"):
            assert leak not in html, f"the public page contains {leak}"

    def test_liveness_is_reachable(self, configured):
        assert configured.get("/health").status_code == 200

    def test_static_assets_are_reachable(self, configured):
        assert configured.get("/static/js/app.js").status_code == 200

    def test_the_status_route_is_reachable_so_the_page_can_ask(self, configured):
        r = configured.get("/api/auth/status")
        assert r.status_code == 200
        assert r.json()["authenticated"] is False
        assert r.json()["required"] is True


class TestSigningIn:
    def _mgmt(self, monkeypatch, *, ok: bool, message: str = "wrong"):
        calls = []

        class _R:
            status_code = 200 if ok else 400
            is_error = not ok
            headers = {"content-type": "application/json"}

            @staticmethod
            def json():
                return {"sid": "SID-1"} if ok else {"message": message}

        class _C:
            async def __aenter__(self): return self
            async def __aexit__(self, *a): return False
            async def post(self, url, json=None, headers=None):
                calls.append((url, json, headers))
                return _R()

        import app.api.auth as mod
        monkeypatch.setattr(mod.httpx, "AsyncClient", lambda **kw: _C())
        return calls

    def test_a_good_password_returns_a_session(self, configured, monkeypatch):
        self._mgmt(monkeypatch, ok=True)
        r = configured.post("/api/auth/login", json={"user": "admin", "password": "s3cret"})
        assert r.status_code == 200
        assert r.json()["user"] == "admin"
        assert auth.COOKIE_NAME in r.cookies or auth.COOKIE_NAME in configured.cookies

    def test_the_session_then_opens_the_gate(self, configured, monkeypatch):
        self._mgmt(monkeypatch, ok=True)
        assert configured.get("/api/runs").status_code == 401
        configured.post("/api/auth/login", json={"user": "admin", "password": "s3cret"})
        assert configured.get("/api/runs").status_code == 200

    def test_the_supplied_password_goes_to_the_management_server_and_nowhere_else(
            self, configured, monkeypatch):
        calls = self._mgmt(monkeypatch, ok=True)
        configured.post("/api/auth/login", json={"user": "admin", "password": "s3cret"})
        urls = [c[0] for c in calls]
        assert any(u.endswith("/web_api/login") for u in urls)
        assert any(u.endswith("/web_api/logout") for u in urls), (
            "the sign-in kept a Management session open")
        # And the cookie carries a username, not the password.
        token = configured.cookies.get(auth.COOKIE_NAME)
        assert "s3cret" not in token
        assert auth.read(token) == "admin"

    def test_a_bad_password_is_refused(self, configured, monkeypatch):
        self._mgmt(monkeypatch, ok=False, message="Authentication failed")
        r = configured.post("/api/auth/login", json={"user": "admin", "password": "no"})
        assert r.status_code == 401
        assert "Authentication failed" in r.json()["detail"]
        assert configured.get("/api/runs").status_code == 401

    def test_signing_out_closes_the_gate_again(self, configured, monkeypatch):
        self._mgmt(monkeypatch, ok=True)
        configured.post("/api/auth/login", json={"user": "admin", "password": "s3cret"})
        assert configured.get("/api/runs").status_code == 200
        configured.post("/api/auth/logout")
        assert configured.get("/api/runs").status_code == 401


class TestItCannotBeUsedToLockAnAdminOut:
    def test_attempts_are_refused_here_rather_than_forwarded(self, configured, monkeypatch):
        calls = TestSigningIn()._mgmt(monkeypatch, ok=False)
        for _ in range(auth.MAX_ATTEMPTS):
            configured.post("/api/auth/login", json={"user": "admin", "password": "x"})
        forwarded = len(calls)

        r = configured.post("/api/auth/login", json={"user": "admin", "password": "x"})
        assert r.status_code == 429
        assert "lock the account out" in r.json()["detail"]
        assert len(calls) == forwarded, (
            "a locked-out attempt still reached the Management Server")

    def test_one_user_being_locked_does_not_lock_another(self, configured, monkeypatch):
        TestSigningIn()._mgmt(monkeypatch, ok=False)
        for _ in range(auth.MAX_ATTEMPTS):
            configured.post("/api/auth/login", json={"user": "alice", "password": "x"})
        assert configured.post("/api/auth/login",
                               json={"user": "alice", "password": "x"}).status_code == 429
        assert configured.post("/api/auth/login",
                               json={"user": "bob", "password": "x"}).status_code == 401

    def test_a_success_clears_the_count(self, configured, monkeypatch):
        TestSigningIn()._mgmt(monkeypatch, ok=False)
        for _ in range(auth.MAX_ATTEMPTS - 1):
            configured.post("/api/auth/login", json={"user": "admin", "password": "x"})
        TestSigningIn()._mgmt(monkeypatch, ok=True)
        assert configured.post("/api/auth/login",
                               json={"user": "admin", "password": "ok"}).status_code == 200
        assert auth.attempts.locked_for("admin") == 0


class TestSetupModeIsStatedNotSilent:
    def test_with_nothing_configured_the_application_is_reachable(self, unconfigured):
        """Otherwise the operator is locked out of the page that fixes it."""
        assert unconfigured.get("/api/credentials/status").status_code == 200

    def test_and_it_says_so(self, unconfigured):
        s = unconfigured.get("/api/auth/status").json()
        assert s["setup_mode"] is True
        assert s["required"] is False
        assert "UNAUTHENTICATED" in s["note"]

    def test_signing_in_is_refused_with_a_reason(self, unconfigured):
        r = unconfigured.post("/api/auth/login", json={"user": "a", "password": "b"})
        assert r.status_code == 409
        assert "Configure them on the Settings page" in r.json()["detail"]


class TestTheSessionToken:
    def test_a_forged_token_is_not_accepted(self, tmp_path, monkeypatch):
        monkeypatch.setattr(auth, "KEY_FILE", tmp_path / ".session_key")
        good = auth.issue("admin")
        body, _ = good.rsplit(".", 1)
        assert auth.read(body + ".notasignature") is None

    def test_a_tampered_username_is_not_accepted(self, tmp_path, monkeypatch):
        import base64, json
        monkeypatch.setattr(auth, "KEY_FILE", tmp_path / ".session_key")
        good = auth.issue("reader")
        _, sig = good.rsplit(".", 1)
        forged = base64.urlsafe_b64encode(
            json.dumps({"u": "root", "iat": 0, "exp": 9999999999}).encode()
        ).decode().rstrip("=")
        assert auth.read(forged + "." + sig) is None

    def test_an_expired_token_is_not_accepted(self, tmp_path, monkeypatch):
        monkeypatch.setattr(auth, "KEY_FILE", tmp_path / ".session_key")
        monkeypatch.setattr(auth, "SESSION_HOURS", -1)
        assert auth.read(auth.issue("admin")) is None

    def test_rubbish_does_not_raise(self, tmp_path, monkeypatch):
        monkeypatch.setattr(auth, "KEY_FILE", tmp_path / ".session_key")
        for bad in (None, "", "x", "x.y", "...", "!!!.???"):
            assert auth.read(bad) is None

    def test_the_key_is_not_the_credential_key(self):
        """Two secrets with different jobs and different blast radiuses."""
        from app import credential_store
        assert auth.KEY_FILE != credential_store.KEY_FILE


def test_the_key_file_is_gitignored():
    from pathlib import Path
    ignored = (Path(__file__).resolve().parent.parent / ".gitignore").read_text(
        encoding="utf-8")
    assert ".session_key" in ignored
