"""
v4.22 - Chapter 6 homework (b): more than two management servers.

`_mgmt_role()` reads `management-blades.secondary`, which answers "is this the
standby?" and nothing else. v4.16 built the whole pairing on the assumption
that the estate contains exactly one primary and at most a handful of
secondaries next to it. Chapter 6 asks what the map does with three servers,
and with two primaries. Reading the code gives three answers, and only one of
them was acceptable:

  1 primary + N secondary   a star, which is what Management HA is.       OK
  2 primary                 nothing drawn, and the reason is stated.      OK
  0 primary + a secondary   nothing drawn, and NOTHING SAID.              bug

The third is the one that matters. A secondary whose primary the API did not
return - filtered by permission, or simply not in the estate - rendered as a
lone management server with no HA marking at all, which is exactly how a
single stand-alone management server renders. The map cannot tell the two
apart, so it must say which one it cannot tell.

And all three answers were being computed across the whole estate at once.
A Multi-Domain estate returns management servers from several domains in one
call; "two primaries" there is not an ambiguity to apologise for, it is two
domains each with its own primary. `domain` is a field the API already sends,
so pairing happens inside a domain rather than across the whole payload.
"""

from app.topology_map import network_map


def mgmt(uid, name, secondary=False, domain=None, ip=None):
    blades = {"logging-and-status": True, "network-policy-management": True}
    if secondary:
        blades["secondary"] = True
    o = {
        "uid": uid, "name": name, "type": "checkpoint-host",
        "ipv4-address": ip or "172.23.31.180",
        "management-blades": blades,
    }
    if domain:
        o["domain"] = {"uid": f"d-{domain}", "name": domain, "domain-type": "domain"}
    return o


def ha_edges(d):
    return [(e["from"], e["to"]) for e in d["edges"] if e.get("kind") == "mgmt-ha"]


def limits(d):
    return " | ".join(d["limitations"])


def test_one_primary_and_one_secondary_is_unchanged():
    d = network_map([mgmt("m1", "CP-MGMT-01"), mgmt("m2", "CP-MGMT-02", secondary=True)])
    assert ha_edges(d) == [("m1", "m2")]
    assert "one primary, 1 secondary" in limits(d)


def test_one_primary_and_two_secondaries_is_a_star():
    d = network_map([
        mgmt("m1", "CP-MGMT-01"),
        mgmt("m2", "CP-MGMT-02", secondary=True),
        mgmt("m3", "CP-MGMT-03", secondary=True),
    ])
    assert sorted(ha_edges(d)) == [("m1", "m2"), ("m1", "m3")]
    assert "1 primary, 2 secondary" in limits(d) or "one primary, 2 secondary" in limits(d)


def test_two_primaries_in_one_domain_still_draw_nothing_and_say_why():
    d = network_map([mgmt("m1", "CP-MGMT-01"), mgmt("m2", "CP-MGMT-02")])
    assert ha_edges(d) == []
    assert "no HA pairing is drawn" in limits(d)
    assert "CP-MGMT-01" in limits(d) and "CP-MGMT-02" in limits(d)


def test_a_secondary_with_no_primary_is_no_longer_silent():
    """The bug this release is for: it used to render as a standalone server."""
    d = network_map([mgmt("m2", "CP-MGMT-02", secondary=True)])
    assert ha_edges(d) == []
    lim = limits(d)
    assert "CP-MGMT-02" in lim
    assert "secondary" in lim.lower()
    assert "no primary" in lim.lower()


def test_each_domain_pairs_within_itself():
    d = network_map([
        mgmt("a1", "MDS-A-Primary", domain="Domain-A", ip="10.0.1.1"),
        mgmt("a2", "MDS-A-Standby", secondary=True, domain="Domain-A", ip="10.0.1.2"),
        mgmt("b1", "MDS-B-Primary", domain="Domain-B", ip="10.0.2.1"),
        mgmt("b2", "MDS-B-Standby", secondary=True, domain="Domain-B", ip="10.0.2.2"),
    ])
    assert sorted(ha_edges(d)) == [("a1", "a2"), ("b1", "b2")]
    # Two primaries exist, but in different domains - that is not ambiguous.
    assert "no HA pairing is drawn" not in limits(d)


def test_a_domain_is_reported_on_the_node_so_the_ui_can_show_it():
    d = network_map([mgmt("a1", "MDS-A-Primary", domain="Domain-A")])
    node = next(n for n in d["nodes"] if n["id"] == "a1")
    assert node["mgmt_domain"] == "Domain-A"


def test_one_healthy_domain_next_to_one_ambiguous_domain():
    d = network_map([
        mgmt("a1", "A-Primary", domain="Domain-A", ip="10.0.1.1"),
        mgmt("a2", "A-Standby", secondary=True, domain="Domain-A", ip="10.0.1.2"),
        mgmt("b1", "B-Primary-1", domain="Domain-B", ip="10.0.2.1"),
        mgmt("b2", "B-Primary-2", domain="Domain-B", ip="10.0.2.2"),
    ])
    assert ha_edges(d) == [("a1", "a2")]
    lim = limits(d)
    assert "Domain-B" in lim
    assert "B-Primary-1" in lim and "B-Primary-2" in lim
    # Domain A is healthy, so it must not be dragged into Domain B's caveat.
    assert "A-Primary" not in lim.split("no HA pairing is drawn")[-1]


def test_a_lone_primary_needs_no_caveat_and_no_edge():
    d = network_map([mgmt("m1", "CP-MGMT-01")])
    assert ha_edges(d) == []
    assert "no primary" not in limits(d).lower()
