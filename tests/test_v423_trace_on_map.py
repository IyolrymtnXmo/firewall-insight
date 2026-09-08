"""
v4.23 - Chapter 6 homework (d): show the traced path on the network map.

The two models do not share a vocabulary. The map knows gateways, interfaces
and connected subnets; the trace knows rules, layers and an action. The join
between them is the only thing in either model that is an address: the
source and destination the person typed, matched against the subnets the map
derived from interface addresses. That match is a fact - an IP either is or is
not inside a prefix.

Everything after the join is weaker, and the overlay has to keep the two kinds
of certainty apart:

  policy certainty    does the rulebase decide this flow (Chapter 4's tri-state)
  topology certainty  do we know the packet goes through THIS box

They fail independently. An exact `accept` whose destination is 8.8.8.8 is a
certain verdict over an uncertain path: the map has no route to the internet,
only an interface a gateway flagged as leading there. A drawing that renders
that identically to a LAN-to-LAN hop states something the data does not
support, which is the same failure `_dimension_cover()` made in v4.17.

So the overlay reports both, and what gets drawn is the weaker of the two.
"""

from app.path_map import trace_overlay
from app.topology_map import network_map


def gw(uid, name, ifaces, typ="simple-gateway"):
    return {"uid": uid, "name": name, "type": typ,
            "ipv4-address": ifaces[0]["ipv4-address"],
            "interfaces": ifaces}


def iface(name, ip, mask=24, internet=False):
    o = {"name": name, "ipv4-address": ip, "ipv4-mask-length": mask}
    if internet:
        o["topology"] = {"leads-to-internet": True}
    return o


INTERNAL = gw("gw-int", "Internal-GW01", [
    iface("eth0", "192.168.10.254"),
    iface("eth1", "192.168.20.254"),
])
EDGE = gw("gw-ext", "External-GW01", [
    iface("eth0", "192.168.20.1"),
    iface("eth1", "203.0.113.9", 30, internet=True),
])

LAN = network_map([INTERNAL])
ESTATE = network_map([INTERNAL, EDGE])


def access(result="Accept", confidence="exact", rule="5", matched=True):
    winner = {"display_rule": rule, "name": "Access-to-RDP", "layer": "Network",
              "action": result}
    return {"matched": matched, "winner": winner if matched else None,
            "possible_winner": None if matched else winner,
            "result": result, "confidence": confidence}


# ---- the join itself --------------------------------------------------

def test_both_endpoints_land_on_the_subnets_the_map_derived():
    o = trace_overlay(LAN, "192.168.10.50", "192.168.20.100", access())
    assert o["source"]["node_id"] == "net:192.168.10.0/24"
    assert o["destination"]["node_id"] == "net:192.168.20.0/24"
    assert o["source"]["state"] == "on-map"
    assert o["destination"]["state"] == "on-map"


def test_the_hop_list_runs_source_subnet_through_the_gateway_to_the_destination():
    o = trace_overlay(LAN, "192.168.10.50", "192.168.20.100", access())
    assert [h["node_id"] for h in o["hops"]] == [
        "net:192.168.10.0/24", "gw-int", "net:192.168.20.0/24"]
    assert o["hops"][1]["name"] == "Internal-GW01"


def test_one_gateway_owning_both_subnets_is_a_certain_topology():
    o = trace_overlay(LAN, "192.168.10.50", "192.168.20.100", access())
    assert o["topology_confidence"] == "exact"
    assert o["draw"] == "exact"


def test_the_most_specific_subnet_wins():
    small = gw("gw-s", "GW-S", [iface("eth0", "10.0.0.1", 8),
                                iface("eth1", "10.1.2.1", 24)])
    m = network_map([small])
    o = trace_overlay(m, "10.1.2.50", "10.9.9.9", access())
    assert o["source"]["node_id"] == "net:10.1.2.0/24"
    assert o["destination"]["node_id"] == "net:10.0.0.0/8"


# ---- the two certainties are separate --------------------------------

def test_an_unverified_verdict_is_never_drawn_like_a_proven_one():
    o = trace_overlay(LAN, "192.168.10.50", "192.168.20.100",
                      access(result="UNVERIFIED", confidence="unknown", matched=False))
    assert o["topology_confidence"] == "exact"      # the path is still known
    assert o["policy_confidence"] == "unknown"
    assert o["draw"] == "unverified"
    assert o["reached"] is False


def test_an_inferred_verdict_drags_an_exact_path_down_to_inferred():
    o = trace_overlay(LAN, "192.168.10.50", "192.168.20.100",
                      access(confidence="inferred"))
    assert o["draw"] == "inferred"


def test_an_exact_verdict_over_an_internet_destination_is_still_only_inferred():
    o = trace_overlay(ESTATE, "192.168.20.50", "8.8.8.8", access())
    assert o["policy_confidence"] == "exact"
    assert o["destination"]["state"] == "off-map"
    assert o["topology_confidence"] == "inferred"
    assert o["draw"] == "inferred"
    assert any("leads-to-internet" in x for x in o["limitations"])


def test_an_off_map_endpoint_with_no_internet_interface_is_not_invented():
    o = trace_overlay(LAN, "192.168.10.50", "8.8.8.8", access())
    assert o["destination"]["state"] == "off-map"
    assert o["destination"]["node_id"] is None
    assert o["topology_confidence"] == "unknown"
    assert o["draw"] == "unverified"
    assert any("not on the map" in x.lower() for x in o["limitations"])


def test_two_gateways_between_the_endpoints_is_inferred_not_exact():
    a = gw("a", "GW-A", [iface("eth0", "192.168.10.254"), iface("eth1", "10.0.0.1", 30)])
    b = gw("b", "GW-B", [iface("eth0", "192.168.20.254"), iface("eth1", "10.0.0.2", 30)])
    o = trace_overlay(network_map([a, b]), "192.168.10.50", "192.168.20.100", access())
    assert o["topology_confidence"] == "inferred"
    assert [h["node_id"] for h in o["hops"]][0] == "net:192.168.10.0/24"
    assert any("more than one enforcement point" in x.lower() for x in o["limitations"])
    assert "GW-A" in " ".join(o["limitations"]) and "GW-B" in " ".join(o["limitations"])


def test_the_verdict_and_the_deciding_rule_travel_with_the_overlay():
    o = trace_overlay(LAN, "192.168.10.50", "192.168.20.100", access(rule="8.1"))
    assert o["verdict"] == "Accept"
    assert o["rule"] == "8.1"
    assert o["layer"] == "Network"


def test_an_empty_map_produces_no_path_and_says_so():
    o = trace_overlay({"nodes": [], "edges": []}, "1.1.1.1", "2.2.2.2", access())
    assert o["hops"] == []
    assert o["draw"] == "none"
    assert o["limitations"]


def test_a_hostname_that_is_not_an_address_does_not_crash_the_overlay():
    o = trace_overlay(LAN, "server.lab.local", "192.168.20.100", access())
    assert o["source"]["state"] == "unresolved"
    assert o["draw"] in ("unverified", "none")


# ---- the drawing has to keep them apart too ---------------------------

class TestTheMapDrawsTheDifference:
    """`draw` in the payload is worth nothing if the SVG paints one style."""

    def setup_method(self):
        from conftest import ui_source
        self.ui = ui_source()

    def test_each_certainty_gets_its_own_line(self):
        css = self.ui
        for style, ok in (("path-exact", "stroke-dasharray:none"),
                          ("path-inferred", "stroke-dasharray:9 5"),
                          ("path-unverified", "stroke-dasharray:2 6")):
            assert f".topo-g-edge.on-path.{style} line" in css, style
            assert ok in css, (style, ok)

    def test_the_difference_is_not_carried_by_colour_alone(self):
        """A colour-blind reader and a greyscale screenshot must both see it."""
        assert ".topo-g-edge.on-path.path-inferred line{stroke:var(--warn);stroke-dasharray:9 5}" in self.ui
        assert ".topo-g-edge.on-path.path-unverified line{stroke:var(--warn);stroke-dasharray:2 6" in self.ui

    def test_the_node_class_comes_from_the_paths_own_certainty(self):
        assert "cls.push('on-path', topoTraceClass());" in self.ui
        assert "'path-' + (t.draw || 'none')" in self.ui

    def test_both_certainties_are_named_in_words_above_the_map(self):
        assert "policy: ${esc(t.policy_confidence)} · topology: ${esc(t.topology_confidence)}" in self.ui

    def test_a_merged_or_collapsed_map_does_not_lose_the_path(self):
        assert "topoTraceResolve" in self.ui
        assert "n.kind === 'merged'" in self.ui
        assert "n.role === 'cluster'" in self.ui

    def test_the_trace_page_offers_the_jump(self):
        assert 'onclick="showTraceOnMap()"' in self.ui
        assert "function clearTraceOnMap()" in self.ui


def test_the_route_returns_the_overlay_and_survives_it_failing():
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "app" / "api" / "traffic.py").read_text(
        encoding="utf-8")
    assert '"map_path": map_path' in src
    assert '"map_path_error": map_path_error' in src
    assert "map_path_error = str(exc)" in src
