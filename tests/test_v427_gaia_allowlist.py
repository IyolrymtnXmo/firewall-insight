"""
v4.27 - adding a second API had to tighten the read-only guarantee, not dilute it.

The Management API made "read-only" cheap to verify: its reads all begin with
`show-`, so a grep for anything else is a proof. The Gaia API does not have
that shape. Its reference lists `show-routes` and `show-cluster-state`
alongside `set-static-route`, `add-license`, `run-script` and `run-reboot` -
same host, same session, same client object.

An application that reaches that API and relies on "we only call the read ones"
has downgraded a structural guarantee to a promise. These tests hold the
guarantee where it was:

  * a command not on the allowlist raises BEFORE any network call, including
    before authentication
  * the allowlist contains only reads
  * no mutating Gaia command string appears anywhere in app/
"""

import asyncio

import pytest

from app.gaia import ALLOWED, SESSION, GaiaClient, GaiaNotAllowed

MUTATING = [
    "set-static-route", "add-static-route", "delete-static-route",
    "run-script", "run-reboot", "add-license", "delete-license",
    "set-interface", "set-initial-setup", "put-file", "set-global-params",
    "set-ssh-server-settings", "set-snmp", "set-allowed-clients",
]


class TestTheAllowlistIsTheOnlyWayIn:
    @pytest.mark.parametrize("command", MUTATING)
    def test_a_mutating_command_is_refused(self, command):
        client = GaiaClient("10.0.0.1", user="x", password="y")
        with pytest.raises(GaiaNotAllowed) as exc:
            asyncio.run(client.call(command))
        assert command in str(exc.value)

    def test_the_refusal_happens_before_any_network_io(self):
        """No connection, no login attempt, no credential on the wire."""
        client = GaiaClient("192.0.2.1", user="x", password="y")

        async def explode(*a, **kw):
            raise AssertionError("a refused command must never reach the transport")

        client._post = explode
        with pytest.raises(GaiaNotAllowed):
            asyncio.run(client.call("run-script", {"script": "id"}))

    def test_login_is_not_reachable_through_call(self):
        """Session commands are handled apart, so the read list stays reads."""
        client = GaiaClient("10.0.0.1", user="x", password="y")
        for command in SESSION:
            with pytest.raises(GaiaNotAllowed):
                asyncio.run(client.call(command))

    def test_every_allowlisted_command_is_a_read(self):
        for command in ALLOWED:
            assert command.startswith("show-"), command

    def test_the_allowlist_is_not_empty_and_covers_what_the_feature_needs(self):
        assert {"show-routes", "show-interfaces", "show-cluster-state"} <= ALLOWED


class TestAnAllowedCommandGoesThrough:
    def test_it_logs_in_once_then_calls(self):
        client = GaiaClient("10.0.0.1", user="u", password="p")
        seen = []

        async def fake_post(command, payload, *, use_sid=True):
            seen.append(command)
            if command == "login":
                return {"sid": "SID-1"}
            return {"objects": []}

        client._post = fake_post
        asyncio.run(client.call("show-routes", {"limit": 10}))
        asyncio.run(client.call("show-interfaces"))
        assert seen == ["login", "show-routes", "show-interfaces"]
        assert client.sid == "SID-1"

    def test_missing_credentials_say_what_to_set(self):
        client = GaiaClient("10.0.0.1", user="", password="")
        with pytest.raises(Exception) as exc:
            asyncio.run(client.call("show-routes"))
        assert "GAIA_USER" in str(exc.value)
        assert "GAIA_ENABLED" in str(exc.value)


class TestNoMutatingGaiaCommandIsAnywhereInTheSource:
    def test_source_scan(self):
        from pathlib import Path
        app_dir = Path(__file__).resolve().parent.parent / "app"
        joined = "\n".join(p.read_text(encoding="utf-8") for p in app_dir.rglob("*.py"))
        # MUTATING itself lives in the tests, not in app/, on purpose.
        for command in ("run-script", "run-reboot", "set-static-route",
                        "add-license", "delete-license", "set-interface"):
            assert f'"{command}"' not in joined, command
            assert f"'{command}'" not in joined, command


class TestItIsOffUntilConfigured:
    def test_the_feature_defaults_to_disabled(self):
        from app.config import Settings
        fresh = Settings(_env_file=None)
        assert fresh.gaia_enabled is False
        assert fresh.gaia_user == ""

    def test_the_example_env_documents_it(self):
        from pathlib import Path
        example = (Path(__file__).resolve().parent.parent / ".env.example").read_text(
            encoding="utf-8")
        assert "GAIA_ENABLED=false" in example
        assert "Only read commands" in example
