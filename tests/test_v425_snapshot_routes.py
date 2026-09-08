"""
v4.25 - the snapshot routes end to end, against a fake Management Server.

The builder and the diff engine are unit-tested apart. This drives the three
routes the way the browser does: capture, list, compare - and checks the two
properties that are easy to lose in wiring. The capture must say where it put
the file, because it is the only write in the application. And a bad snapshot
id must be refused by the route, not just by the store.
"""

from fastapi.testclient import TestClient

import app.main as M
import app.runtime as R
import app.snapshot as store

OBJECTS = [
    {"uid": "any", "name": "Any", "type": "CpmiAnyObject"},
    {"uid": "acc", "name": "Accept", "type": "RulebaseAction"},
    {"uid": "grp", "name": "LAB-Internal-Nets", "type": "group", "members": ["n10"]},
    {"uid": "n10", "name": "LAB-VLAN10", "type": "network",
     "subnet4": "192.168.10.0", "mask-length4": 24},
    {"uid": "n20", "name": "LAB-VLAN20", "type": "network",
     "subnet4": "192.168.20.0", "mask-length4": 24},
    {"uid": "https", "name": "https", "type": "service-tcp", "port": "443"},
]


class Fake:
    hydration_truncated = False
    nat_show_hits_supported = None
    members = ["n10"]

    async def show_package_access_layers(self, package):
        return [{"name": "Network", "uid": "L1"}]

    async def show_rulebase_tree(self, root, max_depth=10):
        objects = [dict(o) for o in OBJECTS]
        for o in objects:
            if o["uid"] == "grp":
                o["members"] = list(self.members)
        return {"root_layer": root, "errors": [], "total_layers": 1, "layers": [{
            "name": root, "uid": "L1", "depth": 0, "path": root,
            "parent_layer": None, "parent_rule": None, "display_prefix": "",
            "rule_count": 1,
            "payload": {"layer": root, "objects-dictionary": objects, "rulebase": [
                {"type": "access-rule", "uid": "R-1", "rule-number": 1,
                 "name": "Lab-Web", "enabled": True, "source": ["grp"],
                 "destination": ["any"], "service": ["https"], "vpn": ["any"],
                 "action": "acc", "install-on": ["any"]},
            ]}}]}

    async def hydrate_objects(self, uids, existing, *, refresh_incomplete=True,
                              on_progress=None):
        return existing

    async def show_nat_rulebase(self, package):
        return {"package": package, "rulebase": [], "objects-dictionary": [], "total": 0}

    async def close(self):
        pass


def client(tmp_path, monkeypatch, fake=None):
    R.cp = fake or Fake()
    R.cache_clear()
    # monkeypatch, not assignment: the module global is process-wide and would
    # otherwise leak a temp directory into every test that ran after this one.
    monkeypatch.setattr(store, "SNAPSHOT_DIR", tmp_path)
    return TestClient(M.app)


def test_capture_list_and_compare(tmp_path, monkeypatch):
    fake = Fake()
    c = client(tmp_path, monkeypatch, fake)

    first = c.get("/api/snapshot", params={"package": "External-FW"})
    assert first.status_code == 200, first.text
    a = first.json()
    assert a["summary"]["access_rules"] == 1
    assert a["saved_to"].endswith(".json")
    assert str(tmp_path) in a["saved_to"], "the only write in the app must say where"

    # The group grows. The rule itself is not touched at all.
    fake.members = ["n10", "n20"]
    R.cache_clear()
    b = c.get("/api/snapshot", params={"package": "External-FW"}).json()
    assert b["id"] != a["id"]

    listed = c.get("/api/snapshots").json()
    assert listed["count"] == 2

    d = c.get("/api/snapshot-diff", params={"a": a["id"], "b": b["id"]})
    assert d.status_code == 200, d.text
    diff = d.json()
    assert diff["summary"]["modified"] == 0, "no field of the rule changed"
    assert diff["summary"]["scope_changed"] == 1
    finding = diff["access"]["scope_changed"][0]
    assert finding["dimension"] == "source"
    assert finding["direction"] == "widened"
    assert "LAB-Internal-Nets" in finding["text"]
    assert diff["identical"] is False
    R.cache_clear()


def test_an_unknown_snapshot_id_is_a_404(tmp_path, monkeypatch):
    c = client(tmp_path, monkeypatch)
    r = c.get("/api/snapshot-diff", params={"a": "nope", "b": "alsonope"})
    assert r.status_code == 404
    R.cache_clear()


def test_a_traversal_attempt_is_a_400_at_the_route(tmp_path, monkeypatch):
    c = client(tmp_path, monkeypatch)
    r = c.get("/api/snapshot-diff", params={"a": "../../.env", "b": "x"})
    assert r.status_code == 400
    assert "snapshot id" in r.json()["detail"]
    R.cache_clear()
