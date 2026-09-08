"""
v4.28 - the readers meet a real gateway, and lose.

`tools/probe_gaia.py` was written so the route readers could be narrowed to
what a build actually answers instead of the shapes the API reference
suggested. Its first run against Check Point Gaia R82 reported:

    parsed: 7/7

and every one of those seven routes came back with `next_hops: []` and
`interface: ""`. The prefix was read, the counter said success, and the field
that says *where the traffic goes* was dropped in silence - including on the
default route, which the gateway plainly reports as via 172.23.34.254.

Gaia nests it one level further than the examples: `next-hop` is an object
carrying a `gateways` list whose entries hold the address AND the egress
interface. A connected route carries only `interface` and correctly has no
gateway at all. Meanwhile `show-static-routes` uses a third shape - a list
keyed `gateway` - which happened to match what was written, so half the
feature looked fine.

Two lessons, both now enforced below:

1. `sys.modules` aside, the oracle is `tests/fixtures/gaia_r82_probe.py`:
   unedited payloads from the lab. Principle 11, applied to a second API.
2. A counter that says "parsed" must mean the route was understood, not that
   one field of it was. A route whose next hop could not be read is now
   counted separately and named on the map.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fixtures.gaia_r82_probe import (  # noqa: E402
    SHOW_ROUTES_GW01, SHOW_STATIC_ROUTES_GW01, UNREACHABLE_GW_INT)

from app.gaia_topology import add_routing, read_routes  # noqa: E402


def by_prefix(result, prefix):
    return next(r for r in result["routes"] if r["prefix"] == prefix)


class TestShowRoutesIsReadProperly:
    def setup_method(self):
        self.out = read_routes(SHOW_ROUTES_GW01)

    def test_the_default_route_keeps_its_next_hop(self):
        """The regression. This was [] on the first live run."""
        route = by_prefix(self.out, "0.0.0.0/0")
        assert route["next_hops"] == ["172.23.34.254"]
        assert route["interface"] == "eth2"
        assert route["next_hop_read"] is True

    def test_a_static_route_to_the_lab_names_the_internal_gateway(self):
        route = by_prefix(self.out, "192.168.10.0/24")
        assert route["next_hops"] == ["172.23.31.176"]
        assert route["interface"] == "eth1"

    def test_a_connected_route_has_no_gateway_and_that_is_correct(self):
        route = by_prefix(self.out, "172.23.31.0/24")
        assert route["next_hops"] == []
        assert route["interface"] == "eth1"
        assert route["connected"] is True
        assert route["next_hop_read"] is True, (
            "a connected route legitimately has no gateway; that is understood, "
            "not unreadable")

    def test_the_protocol_is_read_from_protocol_not_from_type(self):
        assert by_prefix(self.out, "0.0.0.0/0")["type"] == "Static"
        assert by_prefix(self.out, "10.99.99.0/30")["type"] == "Connected"

    def test_every_route_was_understood(self):
        assert self.out["parsed"] == 7
        assert self.out["total"] == 7
        assert self.out["next_hop_unreadable"] == 0
        assert self.out["unparsed"] == []


class TestShowStaticRoutesStillWorks:
    def setup_method(self):
        self.out = read_routes(SHOW_STATIC_ROUTES_GW01)

    def test_the_list_shape_is_read(self):
        assert by_prefix(self.out, "0.0.0.0/0")["next_hops"] == ["172.23.34.254"]
        assert by_prefix(self.out, "192.168.20.0/24")["next_hops"] == ["172.23.31.176"]

    def test_gateway_is_not_mistaken_for_a_routing_protocol(self):
        """`type: gateway` describes the next hop, not how the route was learned."""
        route = by_prefix(self.out, "0.0.0.0/0")
        assert route["type"] != "gateway"
        assert route["next_hop_kind"] == "gateway"


class TestAnUnreadableNextHopIsNotCountedAsParsed:
    def test_a_shape_nobody_modelled_is_flagged(self):
        payload = {"objects": [
            {"address": "10.0.0.0", "mask-length": 8,
             "next-hop": {"something-new-in-a-future-jhf": {"addr": "1.2.3.4"}},
             "protocol": "Static"},
        ]}
        out = read_routes(payload)
        route = out["routes"][0]
        assert route["next_hop_read"] is False
        assert out["next_hop_unreadable"] == 1
        assert out["parsed"] == 0, (
            "the counter must mean the route was understood, not that its prefix was")
        assert out["total"] == 1

    def test_the_prefix_is_still_kept_so_the_map_can_show_it(self):
        payload = {"objects": [{"address": "10.0.0.0", "mask-length": 8,
                                "next-hop": {"mystery": 1}, "protocol": "Static"}]}
        assert read_routes(payload)["routes"][0]["prefix"] == "10.0.0.0/8"


# ---- what the map does with the real data ----------------------------

NETWORK = {
    "nodes": [
        {"id": "gw1", "name": "External-GW01", "role": "cluster-member",
         "ips": ["172.23.31.177"]},
        {"id": "gwint", "name": "Internal-GW01", "role": "gateway",
         "ips": ["172.23.31.176"]},
        {"id": "net:172.23.31.0/24", "name": "172.23.31.0/24", "role": "network"},
        {"id": "net:172.23.34.0/24", "name": "172.23.34.0/24", "role": "network"},
        {"id": "net:10.99.99.0/30", "name": "10.99.99.0/30", "role": "network"},
    ],
    "edges": [], "limitations": [], "count": 5,
}


class TestTheOverlayOnRealData:
    def setup_method(self):
        self.out = add_routing(NETWORK, {
            "172.23.31.177": read_routes(SHOW_ROUTES_GW01),
            "172.23.31.176": UNREACHABLE_GW_INT,
        })
        self.routes = [e for e in self.out["edges"] if e.get("kind") == "route"]

    def test_a_route_whose_next_hop_is_a_known_gateway_links_the_two_devices(self):
        """The insight an interface-only map could never show."""
        edge = next(e for e in self.routes
                    if e["from"] == "gw1" and e["to"] == "gwint")
        assert "192.168.10.0/24" in edge["label"] or "192.168.20.0/24" in edge["label"]
        assert edge["next_hops"] == ["172.23.31.176"]

    def test_the_default_route_becomes_its_own_node_since_nothing_owns_it(self):
        node = next(n for n in self.out["nodes"] if n["id"] == "route:0.0.0.0/0")
        assert node["default_route"] is True

    def test_a_connected_route_to_a_subnet_already_drawn_is_not_drawn_twice(self):
        assert not [e for e in self.routes if e["to"] == "net:172.23.31.0/24"]
        assert self.out["routing"]["connected_confirmed"] >= 3

    def test_loopback_is_skipped_and_said_so_rather_than_dropped(self):
        assert not [e for e in self.routes if "127.0.0" in str(e.get("label"))]
        assert self.out["routing"]["skipped_prefixes"] == ["127.0.0.0/8"]
        assert any("127.0.0.0/8" in x for x in self.out["limitations"])

    def test_the_unreachable_gateway_is_named(self):
        assert any("172.23.31.176" in x for x in self.out["limitations"])
        assert self.out["routing"]["unreachable"]

    def test_nothing_is_reported_as_unreadable_on_this_build(self):
        assert self.out["routing"]["routes_unparsed"] == 0
        assert self.out["routing"]["next_hop_unreadable"] == 0
