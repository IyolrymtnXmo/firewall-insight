"""
v4.38 - a save that mentions two fields must change two fields.

WHAT HAPPENED
The sign-in form offers "use these credentials for my reads too". Ticking it
posts a save carrying a username and a password and nothing else - the Settings
inputs it would otherwise read from have not been rendered yet. `mgmt` was
therefore absent, `CheckPointCreds.mgmt` was declared `str = ""`, and Pydantic
handed the endpoint an empty string that looked exactly like a deliberate one.
It was written to the encrypted store and into the running settings.

`auth.configured()` is `checkpoint_mgmt and checkpoint_user`. With the address
blank it returned False, so the application concluded that nothing was
configured, entered setup mode - which exists so a first-run operator is not
locked out of the page where credentials are entered - and stopped asking
anyone to sign in. The middleware in main.py opens for the same reason. The
header still read "Connected - API 2.0.1", because the Management session
predated the damage.

The symptom reported was "I cleared my cookies and no sign-in page appeared".
The cause was that there was no longer, as far as the application knew, anybody
to check a sign-in against. RISK-01 was silently re-opened by a convenience
checkbox.

This is the v4.31 password bug one field over, so these tests are written
against the class, not the field: a save must carry forward everything it was
not told about.

Every test here runs against a temporary credential file. None of them read or
write the operator's real credentials.enc.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import auth, credential_store
from app.api.credentials import DEFAULTS, NEVER_BLANK, _record
from app.config import settings
from app.main import app

FULL = {
    "mgmt": "https://mgmt.example.invalid",
    "user": "admin",
    "password": "s3cret-lab",
    "domain": "",
    "verify_ssl": True,
    "timeout": 45.0,
    "cache_ttl": 900,
}


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(credential_store, "KEY_FILE", tmp_path / ".credential_key")
    monkeypatch.setattr(credential_store, "ENC_FILE", tmp_path / "credentials.enc")
    return credential_store


@pytest.fixture
def client(store, monkeypatch):
    """A client with the settings restored afterwards.

    `_apply_checkpoint` writes into the process-wide settings object, so
    without this a test would leak its Management URL into the next one.
    """
    keep = {name: getattr(settings, name) for name in dir(settings)
            if name.startswith(("checkpoint_", "gaia_"))}
    yield TestClient(app)
    for name, value in keep.items():
        setattr(settings, name, value)


def _save(client, **fields):
    return client.post("/api/credentials",
                       json={"type": "checkpoint", "checkpoint": fields})


class TestTheSignInShortcutCannotDisarmTheLock:
    """The exact sequence that turned authentication off."""

    def test_a_two_field_save_does_not_blank_the_management_url(self, client, store):
        assert _save(client, **FULL).status_code == 200

        # What signIn() posts when "use these for reads too" is ticked and the
        # Settings page has never been opened: a user and a password, no URL.
        assert _save(client, user="admin", password="s3cret-lab").status_code == 200

        assert store.load("checkpoint")["mgmt"] == FULL["mgmt"], (
            "the Management URL was replaced by the model's default")

    def test_and_the_application_still_asks_people_to_sign_in(self, client, store):
        assert _save(client, **FULL).status_code == 200
        assert auth.configured(), "precondition: the gate is on"

        _save(client, user="admin", password="s3cret-lab")

        assert auth.configured(), (
            "a partial save turned authentication off - setup mode is for an "
            "application with nothing configured, not one that just lost a field")
        state = client.get("/api/auth/status").json()
        assert state["required"] is True
        assert state["setup_mode"] is False

    def test_the_gate_in_front_of_the_data_stays_shut(self, client, store, monkeypatch):
        """configured() feeds the middleware, so prove the middleware too.

        The saves run as the signed-in operator the suite-wide fixture in
        conftest provides - that is who would be pressing Save. The session is
        then dropped, because the question is what a stranger gets afterwards.
        """
        assert _save(client, **FULL).status_code == 200
        _save(client, user="admin", password="s3cret-lab")

        monkeypatch.setattr("app.auth.read", lambda token: None)
        r = client.get("/api/bootstrap")
        assert r.status_code == 401, (
            "an anonymous request reached the estate's data after a partial save")


class TestASaveCarriesForwardWhatItWasNotTold:
    """The general rule, not just the one field that broke."""

    def test_every_untouched_field_survives(self, client, store):
        assert _save(client, **FULL).status_code == 200
        assert _save(client, timeout=30.0).status_code == 200

        saved = store.load("checkpoint")
        for field, expected in FULL.items():
            if field == "timeout":
                continue
            assert saved[field] == expected, f"{field} was lost by an unrelated save"
        assert saved["timeout"] == 30.0, "the field that was sent did not change"

    def test_certificate_verification_is_not_silently_switched_off(self, client, store):
        """The dangerous direction of the same bug.

        `verify_ssl: bool = False` meant any partial save turned certificate
        verification off. That fails open and says nothing.
        """
        assert _save(client, **FULL).status_code == 200
        assert store.load("checkpoint")["verify_ssl"] is True

        _save(client, user="admin", password="s3cret-lab")

        assert store.load("checkpoint")["verify_ssl"] is True, (
            "a save that never mentioned SSL turned certificate verification off")

    def test_an_explicit_value_is_still_honoured(self, client, store):
        """Carrying forward must not become "cannot change it"."""
        assert _save(client, **FULL).status_code == 200
        assert _save(client, verify_ssl=False).status_code == 200
        assert store.load("checkpoint")["verify_ssl"] is False

    def test_a_password_can_still_be_cleared_on_purpose(self, client, store):
        """Blank means "keep" for absent, not for explicitly sent."""
        assert _save(client, **FULL).status_code == 200
        assert _save(client, password="").status_code == 200
        assert store.load("checkpoint")["password"] == ""


class TestARecordAlreadyDamagedIsNotAppliedAgain:
    """The operator's file on disk already holds mgmt: "" from the old build."""

    def test_a_stored_blank_url_does_not_blank_a_configured_one(self, store, monkeypatch):
        monkeypatch.setattr(settings, "checkpoint_mgmt", "https://from-dot-env.invalid")
        monkeypatch.setattr(settings, "checkpoint_user", "admin")

        from app.api.credentials import _apply_checkpoint
        _apply_checkpoint({"mgmt": "", "user": "admin", "password": "x"})

        assert settings.checkpoint_mgmt == "https://from-dot-env.invalid", (
            "a record written by the old build re-broke authentication on startup")
        assert auth.configured()

    def test_a_blank_username_is_treated_the_same_way(self, store, monkeypatch):
        monkeypatch.setattr(settings, "checkpoint_user", "admin")
        from app.api.credentials import _apply_checkpoint
        _apply_checkpoint({"user": ""})
        assert settings.checkpoint_user == "admin"


class TestTheRuleIsWrittenDownWhereItIsEnforced:
    def test_no_field_carries_a_value_typed_default(self):
        """A value-typed default is what caused this, twice.

        The model must be unable to tell the endpoint that an absent field was
        supplied, so every field defaults to None and the real defaults live in
        DEFAULTS where they cannot be confused with an answer.
        """
        from app.api.credentials import CheckPointCreds, GaiaCreds
        for model in (CheckPointCreds, GaiaCreds):
            for name, field in model.model_fields.items():
                assert field.default is None, (
                    f"{model.__name__}.{name} defaults to {field.default!r}; an "
                    f"absent {name} would arrive looking like a deliberate choice")

    def test_defaults_cover_exactly_the_fields_the_models_declare(self):
        from app.api.credentials import CheckPointCreds, GaiaCreds
        assert set(DEFAULTS["checkpoint"]) == set(CheckPointCreds.model_fields)
        assert set(DEFAULTS["gaia"]) == set(GaiaCreds.model_fields)

    def test_the_fields_that_may_never_be_blank_are_the_identity_ones(self):
        """A blank address or account name is a lost value, never a setting."""
        assert NEVER_BLANK == ("mgmt", "user")

    def test_record_falls_back_to_defaults_when_nothing_is_stored(self, store):
        record = _record("checkpoint", {"mgmt": "https://x.invalid", "user": "a"})
        assert record["cache_ttl"] == DEFAULTS["checkpoint"]["cache_ttl"]
        assert record["password"] == ""
