"""
v4.31 - saving a setting must not destroy the password.

The Settings form leaves the password field blank once credentials are saved;
blank is how the UI says "keep the one you already have", and the frontend
drops the key from the request body entirely:

    if (!body.checkpoint.password) delete body.checkpoint.password;

The request model declared `password: str = ""`, so Pydantic materialised the
absent key as an empty string, `credential_store.save()` wrote that over the
stored secret, and `_apply_checkpoint()` pushed it into the running settings.
Changing a timeout and pressing Save therefore wiped the Check Point password
both on disk and in memory, and every following Management API call failed to
log in. Nothing in the suite noticed, because nothing exercised a second save.

These tests run against a temporary credential file - they never read or write
the operator's real `credentials.enc`.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import credential_store
from app.config import settings
from app.main import app


@pytest.fixture
def store(tmp_path, monkeypatch):
    """Point the credential store at a throwaway file and key."""
    monkeypatch.setattr(credential_store, "KEY_FILE", tmp_path / ".credential_key")
    monkeypatch.setattr(credential_store, "ENC_FILE", tmp_path / "credentials.enc")
    return credential_store


@pytest.fixture
def client(store):
    return TestClient(app)


def _save(client, **overrides):
    body = {"mgmt": "https://mgmt.example.invalid", "user": "admin", "timeout": 90.0}
    body.update(overrides)
    return client.post("/api/credentials", json={"type": "checkpoint", "checkpoint": body})


class TestPasswordSurvivesASecondSave:
    def test_a_save_without_a_password_keeps_the_stored_one(self, client, store):
        assert _save(client, password="s3cret-lab").status_code == 200
        assert store.load("checkpoint")["password"] == "s3cret-lab"

        # The user changes only the timeout and presses Save. The form sends no
        # password, exactly as the browser does.
        assert _save(client, timeout=45.0).status_code == 200

        saved = store.load("checkpoint")
        assert saved["password"] == "s3cret-lab", "the stored password was overwritten"
        assert saved["timeout"] == 45.0, "the field the user actually changed was not saved"

    def test_the_running_settings_keep_the_password_too(self, client, store):
        _save(client, password="s3cret-lab")
        _save(client, timeout=45.0)
        assert settings.checkpoint_password == "s3cret-lab"

    def test_an_explicit_empty_password_still_clears_it(self, client, store):
        """Absent means "keep". Empty means "empty" - the value stays clearable."""
        _save(client, password="s3cret-lab")
        _save(client, password="")
        assert store.load("checkpoint")["password"] == ""

    def test_the_same_holds_for_gaia(self, client, store):
        base = {"enabled": True, "user": "admin", "hosts": "10.0.0.1"}
        client.post("/api/credentials", json={"type": "gaia",
                                              "gaia": {**base, "password": "gaia-pw"}})
        assert store.load("gaia")["password"] == "gaia-pw"

        client.post("/api/credentials", json={"type": "gaia", "gaia": base})
        assert store.load("gaia")["password"] == "gaia-pw"


class TestTestConnectionDoesNotLeakTheStoredPassword:
    """`/test` may reuse a saved password, but only against its own host.

    The endpoint takes the target URL from the request body, so an
    unauthenticated caller can choose where this process sends the login. If a
    blank password fell back to the stored secret unconditionally, pointing the
    endpoint at an attacker-controlled host would post the saved Check Point
    password to it.
    """

    def test_a_blank_password_reuses_the_stored_one_for_the_stored_host(self, client, store):
        _save(client, password="s3cret-lab")
        sent = {}

        class _Resp:
            status_code = 200
            is_error = False

            @staticmethod
            def json():
                return {"sid": None, "api-version": "1.9"}

        class _Client:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def post(self, url, json=None, headers=None):
                sent["url"], sent["json"] = url, json
                return _Resp()

        import app.api.credentials as mod
        original = mod.httpx.AsyncClient
        mod.httpx.AsyncClient = lambda **kw: _Client()
        try:
            r = client.post("/api/credentials/test", json={
                "type": "checkpoint",
                "checkpoint": {"mgmt": "https://mgmt.example.invalid", "user": "admin"},
            })
        finally:
            mod.httpx.AsyncClient = original

        assert r.status_code == 200
        assert sent["json"]["password"] == "s3cret-lab"

    def test_a_different_host_never_receives_the_stored_password(self, client, store):
        _save(client, password="s3cret-lab")
        sent = {}

        class _Resp:
            status_code = 200
            is_error = False

            @staticmethod
            def json():
                return {"sid": None}

        class _Client:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def post(self, url, json=None, headers=None):
                sent["url"], sent["json"] = url, json
                return _Resp()

        import app.api.credentials as mod
        original = mod.httpx.AsyncClient
        mod.httpx.AsyncClient = lambda **kw: _Client()
        try:
            client.post("/api/credentials/test", json={
                "type": "checkpoint",
                "checkpoint": {"mgmt": "https://attacker.example.invalid", "user": "admin"},
            })
        finally:
            mod.httpx.AsyncClient = original

        assert sent["json"]["password"] == "", (
            "the stored password was sent to a host it was not stored for")


def test_importing_the_app_does_not_read_the_credential_file(monkeypatch):
    """Decryption belongs to startup, not to `import app.main`.

    `load_credentials_on_startup()` used to run as a module-level call at the
    bottom of api/credentials.py, so merely importing the application - during
    test collection, for instance - decrypted the operator's secrets.
    """
    source = (credential_store.Path(__file__).resolve().parent.parent
              / "app" / "api" / "credentials.py").read_text(encoding="utf-8")
    body = source.split("# ── endpoints", 1)[1]
    assert "\nload_credentials_on_startup()" not in body

    main = (credential_store.Path(__file__).resolve().parent.parent
            / "app" / "main.py").read_text(encoding="utf-8")
    assert "load_credentials_on_startup()" in main
