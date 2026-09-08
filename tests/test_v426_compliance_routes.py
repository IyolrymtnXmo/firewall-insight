"""
v4.26 - a compliance run through the real routes.

The engine is unit-tested apart. What this proves is the part that only breaks
in the wiring: that a live run supplies the analyses (so analysis-backed checks
can be decided) while a run against a stored snapshot does not (so those same
checks come back `unverifiable` rather than passing on absent evidence).

That asymmetry is the feature, not a limitation to paper over: the same profile
against the same policy answers differently depending on how much evidence the
run actually had, and says which.
"""

from fastapi.testclient import TestClient

import app.compliance as engine
import app.main as M
import app.runtime as R
import app.snapshot as store

OBJECTS = [
    {"uid": "any", "name": "Any", "type": "CpmiAnyObject"},
    {"uid": "acc", "name": "Accept", "type": "RulebaseAction"},
    {"uid": "drop", "name": "Drop", "type": "RulebaseAction"},
    {"uid": "log", "name": "Log", "type": "Track"},
    {"uid": "none", "name": "None", "type": "Track"},
    {"uid": "lab", "name": "LAB-VLAN10", "type": "network",
     "subnet4": "192.168.10.0", "mask-length4": 24},
    {"uid": "telnet", "name": "telnet", "type": "service-tcp", "port": "23"},
]


class Fake:
    hydration_truncated = False
    nat_show_hits_supported = None

    async def show_package_access_layers(self, package):
        return [{"name": "Network", "uid": "L1"}]

    async def show_rulebase_tree(self, root, max_depth=10):
        return {"root_layer": root, "errors": [], "total_layers": 1, "layers": [{
            "name": root, "uid": "L1", "depth": 0, "path": root,
            "parent_layer": None, "parent_rule": None, "display_prefix": "",
            "rule_count": 2,
            "payload": {"layer": root, "objects-dictionary": OBJECTS, "rulebase": [
                {"type": "access-rule", "uid": "R-1", "rule-number": 1,
                 "name": "Legacy-Telnet", "enabled": True, "source": ["lab"],
                 "destination": ["any"], "service": ["telnet"], "vpn": ["any"],
                 "action": "acc", "track": "log", "install-on": ["any"],
                 "comments": "left over from 2019"},
                {"type": "access-rule", "uid": "R-9", "rule-number": 9,
                 "name": "Cleanup rule", "enabled": True, "source": ["any"],
                 "destination": ["any"], "service": ["any"], "vpn": ["any"],
                 "action": "drop", "track": "log", "install-on": ["any"],
                 "comments": "explicit cleanup"},
            ]}}]}

    async def hydrate_objects(self, uids, existing, *, refresh_incomplete=True,
                              on_progress=None):
        return existing

    async def show_nat_rulebase(self, package):
        return {"package": package, "rulebase": [], "objects-dictionary": [], "total": 0}

    async def show_gateways_and_servers(self):
        return []

    async def close(self):
        pass


def client(tmp_path, monkeypatch):
    R.cp = Fake()
    R.cache_clear()
    monkeypatch.setattr(store, "SNAPSHOT_DIR", tmp_path)
    return TestClient(M.app)


def status_of(payload, check_id):
    return next(r["status"] for r in payload["results"] if r["id"] == check_id)


def test_the_profiles_are_listed(tmp_path, monkeypatch):
    d = client(tmp_path, monkeypatch).get("/api/compliance-profiles").json()
    ids = {p["id"] for p in d["profiles"]}
    assert {"nist-800-41-baseline", "house-hygiene"} <= ids
    R.cache_clear()


def test_a_live_run_decides_the_analysis_backed_checks(tmp_path, monkeypatch):
    c = client(tmp_path, monkeypatch)
    r = c.get("/api/compliance", params={"profile": "house-hygiene", "package": "External-FW"})
    assert r.status_code == 200, r.text
    d = r.json()

    # The telnet rule is real and provable, so it fails - by name.
    assert status_of(d, "HOUSE-NO-TELNET") == "fail"
    offender = next(x for x in d["results"] if x["id"] == "HOUSE-NO-TELNET")["offenders"][0]
    assert offender["name"] == "Legacy-Telnet"

    # The shadow check needs the access analysis, which a live run has.
    assert status_of(d, "HOUSE-NO-SHADOWED") in ("pass", "fail")
    assert d["conformant"] is False
    assert d["evaluated"]["kind"] == "live"
    assert d["evaluated"]["snapshot_id"], "a live run leaves evidence behind"
    R.cache_clear()


def test_the_same_profile_on_a_stored_snapshot_admits_what_it_cannot_decide(tmp_path, monkeypatch):
    c = client(tmp_path, monkeypatch)
    live = c.get("/api/compliance",
                 params={"profile": "house-hygiene", "package": "External-FW"}).json()
    sid = live["evaluated"]["snapshot_id"]

    d = c.get("/api/compliance",
              params={"profile": "house-hygiene", "snapshot": sid}).json()
    assert d["evaluated"] == {"kind": "snapshot", "id": sid}
    # Rule-level checks still decide.
    assert status_of(d, "HOUSE-NO-TELNET") == "fail"
    # Analysis-backed ones do not, and say so instead of passing.
    assert status_of(d, "HOUSE-NO-SHADOWED") == "unverifiable"
    assert status_of(d, "HOUSE-NAT-NO-BROAD") == "unverifiable"
    assert d["conformant"] is False
    R.cache_clear()


def test_the_nist_profile_passes_where_the_policy_earns_it(tmp_path, monkeypatch):
    c = client(tmp_path, monkeypatch)
    d = c.get("/api/compliance",
              params={"profile": "nist-800-41-baseline", "package": "External-FW"}).json()
    assert status_of(d, "NIST-DENY-DEFAULT-ANY-PERMIT") == "pass"
    assert status_of(d, "NIST-DENY-DEFAULT-CLEANUP") == "pass"
    assert status_of(d, "NIST-REVIEWABLE-RULES") == "pass"
    assert d["conformant"] is True
    # And even a fully conformant run says what it did not look at.
    assert len(d["not_checkable"]) >= 3
    R.cache_clear()


def test_neither_source_is_a_400_and_a_bad_profile_a_404(tmp_path, monkeypatch):
    c = client(tmp_path, monkeypatch)
    assert c.get("/api/compliance", params={"profile": "house-hygiene"}).status_code == 400
    assert c.get("/api/compliance", params={"profile": "nope",
                                            "package": "X"}).status_code == 404
    assert c.get("/api/compliance", params={"profile": "../../.env",
                                            "package": "X"}).status_code == 400
    R.cache_clear()
