"""
v4.23 - the overlay through the real route, not just the pure function.

`trace_overlay()` is unit-tested next door. This exercises the wiring: that
/api/traffic-path fetches the gateway list, joins it to the trace it just ran,
and returns the overlay - and that when the gateway call fails, the Access
verdict still comes back. An overlay that takes the answer down with it would
be a worse tool than one that has no overlay at all.
"""

from fastapi.testclient import TestClient

import app.main as M
import app.runtime as R

OBJS = [
    {"uid": "any", "name": "Any", "type": "CpmiAnyObject"},
    {"uid": "acc", "name": "Accept", "type": "RulebaseAction"},
    {"uid": "lab", "name": "LAB-VLAN10", "type": "network",
     "subnet4": "192.168.10.0", "mask-length4": 24},
    {"uid": "srv", "name": "RDP-Server", "type": "host", "ipv4-address": "192.168.20.100"},
    {"uid": "rdp", "name": "Remote_Desktop_Protocol", "type": "service-tcp", "port": "3389"},
]

GATEWAYS = [{
    "uid": "gw-int", "name": "Internal-GW01", "type": "simple-gateway",
    "ipv4-address": "192.168.10.254",
    "interfaces": [
        {"name": "eth0", "ipv4-address": "192.168.10.254", "ipv4-mask-length": 24},
        {"name": "eth1", "ipv4-address": "192.168.20.254", "ipv4-mask-length": 24},
    ],
}]


class _Fake:
    hydration_truncated = False
    nat_show_hits_supported = None
    gateways_fail = False

    async def show_package_access_layers(self, package):
        return [{"name": "Network", "uid": "u1"}]

    async def show_rulebase_tree(self, root, max_depth=10):
        rules = [{"type": "access-rule", "rule-number": 5, "name": "Access-to-RDP",
                  "enabled": True, "source": ["lab"], "destination": ["srv"],
                  "service": ["rdp"], "action": "acc"}]
        return {"root_layer": root, "errors": [], "total_layers": 1, "layers": [{
            "name": root, "uid": "u1", "depth": 0, "path": root,
            "parent_layer": None, "parent_rule": None, "display_prefix": "",
            "rule_count": 1,
            "payload": {"layer": root, "rulebase": rules, "objects-dictionary": OBJS},
        }]}

    async def hydrate_objects(self, uids, existing, *, refresh_incomplete=True,
                              on_progress=None):
        return existing

    async def show_nat_rulebase(self, package):
        return {"package": package, "rulebase": [], "objects-dictionary": [], "total": 0}

    async def show_gateways_and_servers(self):
        if self.gateways_fail:
            from app.checkpoint import CheckPointAPIError
            raise CheckPointAPIError("show-gateways-and-servers: permission denied")
        return GATEWAYS

    async def close(self):
        pass


def _trace(fake):
    R.cp = fake
    R.cache_clear()
    return TestClient(M.app).get("/api/traffic-path", params={
        "layer": "Network", "src": "192.168.10.50", "dst": "192.168.20.100",
        "protocol": "tcp", "service": "3389", "package": "External-FW",
    })


def test_the_route_joins_the_trace_to_the_map():
    r = _trace(_Fake())
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["access"]["matched"] is True
    mp = d["map_path"]
    assert mp is not None
    assert [h["node_id"] for h in mp["hops"]] == [
        "net:192.168.10.0/24", "gw-int", "net:192.168.20.0/24"]
    assert mp["policy_confidence"] == "exact"
    assert mp["topology_confidence"] == "exact"
    assert mp["draw"] == "exact"
    assert mp["rule"] == "5"
    R.cache_clear()


def test_a_failing_gateway_call_costs_the_overlay_and_nothing_else():
    fake = _Fake()
    fake.gateways_fail = True
    r = _trace(fake)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["access"]["matched"] is True          # the answer survives
    assert d["access"]["winner"]["action"] == "Accept"
    assert d["map_path"] is None
    assert "permission denied" in d["map_path_error"]
    R.cache_clear()
