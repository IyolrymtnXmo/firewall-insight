"""
v4.27 - reading routing without a verified sample of the payload.

The Gaia API's envelopes differ between builds, and this application has no
lab-confirmed sample of every one. Writing a parser against a shape assumed
from documentation is exactly the move README principle 11 forbids, so the
readers try the plausible keys and - the part that matters - report what they
could not read instead of dropping it.

A routing map that silently omits the four routes it did not understand is
worse than one that says it read six of ten, because the first one looks
finished.
"""

from app.gaia_topology import add_routing, read_routes

# Three envelopes that all plausibly come back from `show-routes`, written to
# be different in every way the readers have to tolerate.
SHAPE_A = {"objects": [
    {"destination": "192.168.20.0", "mask-length": 24, "next-hop": "10.99.99.2",
     "type": "static", "interface": "eth1"},
    {"destination": "0.0.0.0", "mask-length": 0, "next-hop": "172.23.31.254",
     "type": "static"},
]}
SHAPE_B = {"routes": [
    {"address": "192.168.20.0/24", "next_hop": [{"gateway": "10.99.99.2"}],
     "route-type": "static", "device": "eth1"},
    {"address": "default", "next_hop": "172.23.31.254", "route-type": "static"},
]}
SHAPE_C = [
    {"network": "192.168.20.0/24", "via": "10.99.99.2", "protocol": "S", "dev": "eth1"},
]


class TestTheReaderToleratesShapes:
    def test_shape_a(self):
        out = read_routes(SHAPE_A)
        assert out["parsed"] == 2
        assert out["routes"][0]["prefix"] == "192.168.20.0/24"
        assert out["routes"][0]["next_hops"] == ["10.99.99.2"]
        assert out["routes"][1]["prefix"] == "0.0.0.0/0"

    def test_shape_b_including_a_dict_next_hop_and_the_word_default(self):
        out = read_routes(SHAPE_B)
        assert out["parsed"] == 2
        assert out["routes"][0]["next_hops"] == ["10.99.99.2"]
        assert out["routes"][0]["interface"] == "eth1"
        assert out["routes"][1]["prefix"] == "0.0.0.0/0"

    def test_a_bare_list_is_accepted(self):
        out = read_routes(SHAPE_C)
        assert out["parsed"] == 1
        assert out["routes"][0]["type"] == "S"

    def test_an_unreadable_entry_is_kept_not_dropped(self):
        out = read_routes({"objects": [
            {"destination": "192.168.20.0", "mask-length": 24},
            {"comment": "something this build returns that we do not model"},
            {"destination": "not-an-address", "mask-length": 24},
        ]})
        # v4.28: the first entry has a legible prefix and NO next hop of any
        # kind, so it is no longer counted as parsed. The live probe showed why:
        # a counter that says 7/7 while every hop was dropped is worse than no
        # counter. The prefix is still kept - see the next assertion.
        assert out["parsed"] == 0
        assert out["next_hop_unreadable"] == 1
        assert out["routes"][0]["prefix"] == "192.168.20.0/24"
        assert len(out["unparsed"]) == 2
        assert out["total"] == 3
        assert out["unparsed"][0]["raw"] == {"comment": "something this build returns that we do not model"}

    def test_an_empty_or_unknown_payload_is_zero_not_a_crash(self):
        for payload in ({}, None, {"weird": {}}, "nonsense"):
            assert read_routes(payload)["parsed"] == 0


# ---- overlaying onto the map -----------------------------------------

NETWORK = {
    "nodes": [
        {"id": "gw-ext", "name": "External-GW01", "role": "gateway",
         "ips": ["172.23.31.177"]},
        {"id": "net:192.168.20.0/24", "name": "192.168.20.0/24", "role": "network",
         "ips": ["192.168.20.0/24"]},
    ],
    "edges": [],
    "limitations": ["existing caveat"],
    "count": 2,
}


def routes_of(payload):
    return read_routes(payload)


class TestTheOverlay:
    def test_a_route_to_a_known_subnet_links_to_that_subnet(self):
        out = add_routing(NETWORK, {"External-GW01": routes_of(SHAPE_A)})
        edge = next(e for e in out["edges"]
                    if e.get("kind") == "route" and e["to"] == "net:192.168.20.0/24")
        assert edge["from"] == "gw-ext"
        assert "10.99.99.2" in edge["label"]

    def test_a_route_to_an_unknown_prefix_becomes_its_own_node(self):
        out = add_routing(NETWORK, {"External-GW01": routes_of(SHAPE_A)})
        node = next(n for n in out["nodes"] if n["id"] == "route:0.0.0.0/0")
        assert node["role"] == "routed-network"
        assert node["default_route"] is True

    def test_a_gateway_can_be_addressed_by_ip_as_well_as_name(self):
        out = add_routing(NETWORK, {"172.23.31.177": routes_of(SHAPE_C)})
        assert any(e.get("kind") == "route" for e in out["edges"])

    def test_the_original_map_is_not_mutated(self):
        before_nodes = len(NETWORK["nodes"])
        add_routing(NETWORK, {"External-GW01": routes_of(SHAPE_A)})
        assert len(NETWORK["nodes"]) == before_nodes
        assert NETWORK["edges"] == []

    def test_routing_is_declared_a_snapshot_not_a_live_view(self):
        out = add_routing(NETWORK, {"External-GW01": routes_of(SHAPE_A)})
        assert any("snapshot of" in x and "not a live view" in x
                   for x in out["limitations"])

    def test_unparsed_routes_are_counted_on_the_map_itself(self):
        result = read_routes({"objects": [{"nope": 1}, {"nope": 2}]})
        out = add_routing(NETWORK, {"External-GW01": result})
        assert out["routing"]["routes_unparsed"] == 2
        assert any("could not be read at all and are NOT" in x
                   for x in out["limitations"])

    def test_a_gateway_that_could_not_be_read_is_named_not_omitted(self):
        out = add_routing(NETWORK, {
            "External-GW01": routes_of(SHAPE_A),
            "Internal-GW01": {"error": "connection refused"},
        })
        assert "Internal-GW01" in " ".join(out["limitations"])
        assert out["routing"]["unreachable"]
        assert out["routing"]["gateways_read"] == 1

    def test_a_gateway_not_on_the_map_is_reported_rather_than_drawn_loose(self):
        out = add_routing(NETWORK, {"Some-Other-Box": routes_of(SHAPE_A)})
        assert any("is not a node on this map" in x for x in out["limitations"])
        assert not [e for e in out["edges"] if e.get("kind") == "route"]

    def test_no_routing_data_at_all_still_returns_a_usable_map(self):
        out = add_routing(NETWORK, {})
        assert out["count"] == 2
        assert out["routing"]["routes_parsed"] == 0


# ---- the route, and the difference between "off" and "none" -----------

class TestTheMapRoute:
    def _client(self, monkeypatch, *, enabled, per_gateway=None):
        from fastapi.testclient import TestClient
        import app.api.topology as topo
        import app.main as M
        import app.runtime as R

        class Fake:
            async def show_gateways_and_servers(self):
                return [{"uid": "gw", "name": "External-GW01", "type": "simple-gateway",
                         "ipv4-address": "172.23.31.177",
                         "interfaces": [{"name": "eth0", "ipv4-address": "172.23.31.177",
                                         "ipv4-mask-length": 24}]}]
            async def close(self):
                pass

        R.cp = Fake()
        R.cache_clear()
        monkeypatch.setattr(topo.settings, "gaia_enabled", enabled)

        async def fake_read_all_routes():
            return per_gateway or {}
        monkeypatch.setattr(topo, "read_all_routes", fake_read_all_routes)
        return TestClient(M.app)

    def test_without_routing_the_map_is_exactly_what_it_was(self, monkeypatch):
        c = self._client(monkeypatch, enabled=True)
        d = c.get("/api/network-map").json()
        assert "routing" not in d
        assert not [e for e in d["edges"] if e.get("kind") == "route"]

    def test_asking_for_routing_while_it_is_disabled_says_so(self, monkeypatch):
        """The whole point: 'I did not look' must not render as 'nothing there'."""
        c = self._client(monkeypatch, enabled=False)
        d = c.get("/api/network-map", params={"routing": "true"}).json()
        assert d["routing"] == {"enabled": False}
        assert any("GAIA_ENABLED is false" in x for x in d["limitations"])
        assert any("not evidence that the gateways have no routes" in x
                   for x in d["limitations"])

    def test_routing_is_overlaid_when_enabled(self, monkeypatch):
        c = self._client(monkeypatch, enabled=True, per_gateway={
            "172.23.31.177": read_routes(SHAPE_A)})
        d = c.get("/api/network-map", params={"routing": "true"}).json()
        assert d["routing"]["enabled"] is True
        assert d["routing"]["routes_parsed"] == 2
        assert [e for e in d["edges"] if e.get("kind") == "route"]

    def test_the_ui_distinguishes_the_two_cases(self):
        from conftest import ui_source
        ui = ui_source()
        assert "Routing not read" in ui
        assert "not evidence that the gateways have no routes" in ui
        assert "Some routes could not be parsed" in ui
        assert ".topo-g-edge.route line" in ui, (
            "a route edge must not be drawn like an interface-derived subnet link")
