"""
v4.39 - alerts that say what they know, and admit when they failed to send.

Held to:
    one definition of a review's outcome, shared with the CLI exit code
    "could not read" alerts by default - silence must not mean "fine"
    summary alerts carry no rule contents and no addresses
    a webhook URL and an SMTP password are never returned by the API
    a webhook URL must be https (plain http only to this machine)
    a failed delivery is recorded on the run, never raised into it
    the alerts route module cannot reach the policy layer
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from app.jobs import alerts, store
from app.main import app

APP = Path(__file__).resolve().parent.parent / "app"


def _run(*, changed=0, unverifiable=0, compliance=None, gateways=None, incomplete=()):
    sections = {
        "access": {"requested": True, "ok": True, "data": {"summary": {}}},
        "changed": {"requested": True, "ok": True, "data": {
            "first_run": False,
            "summary": {"modified": changed, "scope_unverifiable": unverifiable}}},
        "compliance": compliance or {"requested": False, "ok": False, "data": None},
        "gateways": gateways or {"requested": False, "ok": False, "data": None},
    }
    return {"id": "P-1", "package": "P", "started_at": "2026-09-13T09:00:00",
            "sections": sections, "incomplete_sections": list(incomplete)}


GATEWAYS_BAD = {"requested": True, "ok": True, "data": {"findings": [
    {"severity": "high", "kind": "not-read", "host": "192.0.2.9", "subject": "reachability"}]}}


class TestOneOutcome:
    def test_verdicts(self):
        assert store.outcome(_run())["verdict"] == "clean"
        assert store.outcome(_run(changed=2))["verdict"] == "attention"
        assert store.outcome(_run(unverifiable=1))["verdict"] == "undecided"
        assert store.outcome(_run(changed=2, incomplete=["gateways"]))["verdict"] == "undecided"

    def test_it_agrees_with_the_cli_exit_code(self):
        from tools.run_review import EXIT_CHANGED, EXIT_UNCHANGED, EXIT_UNDECIDED, _exit_code
        mapping = {"clean": EXIT_UNCHANGED, "attention": EXIT_CHANGED, "undecided": EXIT_UNDECIDED}
        for run in (_run(), _run(changed=1), _run(unverifiable=3),
                    _run(incomplete=["compliance"]),
                    _run(compliance={"requested": True, "ok": True,
                                     "data": {"conformant": False, "summary": {"failed": 2}}})):
            assert _exit_code(run) == mapping[store.outcome(run)["verdict"]], run


class TestWhenItFires:
    def test_undecided_is_on_by_default(self):
        """A review that could not read is the one whose silence is misread."""
        d = alerts.normalise({"kind": "slack"})
        assert "undecided" in d["on"]

    def test_a_clean_run_does_not_fire_the_default(self):
        met = alerts.triggers_met(store.outcome(_run()))
        assert not met & set(alerts.DEFAULT_TRIGGERS)

    def test_an_unreachable_gateway_fires_health(self):
        met = alerts.triggers_met(store.outcome(_run(gateways=GATEWAYS_BAD)))
        assert "health" in met


class TestWhatItSays:
    def test_summary_carries_no_addresses(self):
        msg = alerts.build_message(_run(gateways=GATEWAYS_BAD), "summary")
        text = json.dumps(msg)
        assert "192.0.2.9" not in text
        assert "did not answer" in " ".join(msg["lines"])

    def test_findings_detail_may(self):
        msg = alerts.build_message(_run(gateways=GATEWAYS_BAD), "findings")
        assert "192.0.2.9" in " ".join(msg["lines"])

    def test_could_not_compare_is_said_separately_from_changed(self):
        msg = alerts.build_message(_run(unverifiable=2), "summary")
        joined = " ".join(msg["lines"])
        assert "No rule changed" in joined and "2 rule(s) could not be compared" in joined
        assert "could not be fully read" in msg["title"]

    def test_teams_is_an_adaptive_card_and_slack_has_fallback_text(self):
        msg = alerts.build_message(_run(changed=1))
        t = alerts.payload("teams", msg)
        assert t["attachments"][0]["contentType"] == "application/vnd.microsoft.card.adaptive"
        assert t["attachments"][0]["content"]["type"] == "AdaptiveCard"
        s = alerts.payload("slack", msg)
        assert s["text"] and s["blocks"]


class TestSecrets:
    def test_urls_must_be_https_except_to_this_machine(self):
        assert alerts.check_url("https://hooks.slack.com/services/x")
        assert alerts.check_url("http://127.0.0.1:9000/hook")
        with pytest.raises(ValueError):
            alerts.check_url("http://example.invalid/hook")

    def test_the_api_never_returns_a_url_or_password(self):
        c = TestClient(app)
        secret = "https://hooks.example.invalid/SECRET-TOKEN-123"
        r = c.put("/api/alerts/destinations", json={
            "destination": {"kind": "webhook", "name": "ops"}, "url": secret})
        assert r.status_code == 200, r.text
        r2 = c.put("/api/alerts/destinations", json={
            "destination": {"kind": "email", "name": "exec", "smtp_host": "smtp.example.invalid",
                            "sender": "fi@example.invalid", "to": "cso@example.invalid"},
            "password": "PW-DO-NOT-RETURN"})
        assert r2.status_code == 200, r2.text
        body = c.get("/api/alerts").text
        assert "SECRET-TOKEN-123" not in body and "PW-DO-NOT-RETURN" not in body
        cfg = c.get("/api/alerts").json()
        assert {d["id"]: d["url_set"] for d in cfg["destinations"]}["webhook-ops"] is True

    def test_the_config_file_holds_no_secret(self):
        alerts.save_destination({"kind": "slack", "name": "x"}, url="https://hooks.example.invalid/T0K")
        assert "T0K" not in alerts.CONFIG_FILE.read_text(encoding="utf-8")


class TestDelivery:
    def _transport(self, seen, status=200):
        def handler(request: httpx.Request):
            seen.append(json.loads(request.content))
            return httpx.Response(status, text="ok" if status < 300 else "nope")
        return httpx.MockTransport(handler)

    def test_a_webhook_receives_the_alert(self):
        alerts.save_destination({"kind": "webhook", "name": "w"}, url="https://hooks.example.invalid/w")
        seen = []
        res = asyncio.run(alerts.dispatch(_run(changed=1), transport=self._transport(seen)))
        assert res[0]["ok"] is True and seen and seen[0]["verdict"] == "attention"

    def test_a_failed_delivery_is_recorded_not_raised(self):
        alerts.save_destination({"kind": "slack", "name": "s"}, url="https://hooks.example.invalid/s")
        res = asyncio.run(alerts.dispatch(_run(changed=1), transport=self._transport([], 500)))
        assert res[0]["ok"] is False and "HTTP 500" in res[0]["error"]

    def test_a_destination_whose_triggers_are_not_met_is_skipped_with_a_reason(self):
        alerts.save_destination({"kind": "webhook", "name": "w", "on": ["attention"]},
                                url="https://hooks.example.invalid/w")
        res = asyncio.run(alerts.dispatch(_run(), transport=self._transport([])))
        assert res[0]["ok"] is None and "clean" in res[0]["skipped"]

    def test_email_is_sent_with_the_pdf(self, monkeypatch):
        sent = []

        class FakeSMTP:
            def __init__(self, host, port, **kw):
                self.host, self.port = host, port
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def starttls(self, **kw): sent.append("starttls")
            def login(self, u, p): sent.append(("login", u, p))
            def send_message(self, m): sent.append(m)

        monkeypatch.setattr("app.jobs.report.build_report", lambda run, detail: b"%PDF-fake")
        alerts.save_destination({"kind": "email", "name": "e", "smtp_host": "smtp.example.invalid",
                                 "sender": "fi@example.invalid", "to": ["a@example.invalid"],
                                 "username": "fi"}, password="pw")
        res = asyncio.run(alerts.dispatch(_run(changed=1), smtp_factory=FakeSMTP))
        assert res[0]["ok"] is True, res
        assert "starttls" in sent and ("login", "fi", "pw") in sent
        message = sent[-1]
        assert message["To"] == "a@example.invalid"
        assert any(part.get_filename() == "P-1.pdf" for part in message.iter_attachments())


class TestBoundary:
    def test_the_alerts_modules_do_not_reach_the_policy_layer(self):
        for path in (APP / "jobs" / "alerts.py", APP / "api" / "alerts.py"):
            text = path.read_text(encoding="utf-8")
            for forbidden in ("from ..policy", "from ...policy", "checkpoint import",
                              "runtime import cp", "web_api/", "gaia_api/"):
                assert forbidden not in text, f"{path.name} reaches {forbidden}"
