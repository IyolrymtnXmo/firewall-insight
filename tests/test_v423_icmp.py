"""
v4.23 - Chapter 4 homework (c) turned out to hide a gap: ICMP.

The homework says to add an acceptance case for rule 7, and warns that it must
carry `"protocol": "icmp"` rather than tcp. Following that warning to the code
shows the resolver has modelled ICMP since v4.10 - `_leaf_service_atoms()`
gives an icmp object a PortAtom tagged `icmp`, precisely so an ICMP-only
service can be a confident no-match against a TCP query instead of poisoning
the rule with `unknown`.

The gap was above it. The protocol selector on the Traffic Path page offered
tcp and udp only, so no ICMP rule in any policy could be traced from the UI at
all, and the display formatted an ICMP query as `ICMP/8`, borrowing port
notation for a protocol that has no ports.
"""

from app.resolver import ObjectResolver
from app.traffic import resolve_service_query, trace_access_tree


def res(*objects):
    return ObjectResolver({o["uid"]: o for o in objects})


ECHO = {"uid": "u-echo", "name": "echo-request", "type": "service-icmp", "icmp-type": 8}
HTTPS = {"uid": "u-https", "name": "https", "type": "service-tcp", "port": "443"}


def test_a_numeric_icmp_type_resolves():
    q = resolve_service_query("8", "icmp", res(ECHO))
    assert q["protocol"] == "icmp"
    assert q["atoms"] == [("icmp", 8, 8)]


def test_an_icmp_query_is_not_displayed_in_port_notation():
    q = resolve_service_query("8", "icmp", res(ECHO))
    assert "/" not in q["display"], q["display"]
    assert "ICMP" in q["display"] and "8" in q["display"]


def test_an_icmp_service_object_resolves_by_name():
    q = resolve_service_query("echo-request", "icmp", res(ECHO, HTTPS))
    assert q["resolved_by"] == "checkpoint-service-object"
    assert q["atoms"] == [("icmp", 8, 8)]
    assert not q.get("warnings")


def test_a_tcp_query_is_a_confident_no_match_against_an_icmp_rule():
    """The reason the resolver tags the protocol at all."""
    objects = [
        {"uid": "any", "name": "Any", "type": "CpmiAnyObject"},
        {"uid": "acc", "name": "Accept", "type": "RulebaseAction"},
        {"uid": "drop", "name": "Drop", "type": "RulebaseAction"},
        ECHO, HTTPS,
    ]
    payload = {"objects-dictionary": objects, "rulebase": [
        {"type": "access-rule", "rule-number": 7, "name": "Lab-ICMP", "enabled": True,
         "source": ["any"], "destination": ["any"], "service": ["u-echo"], "action": "acc"},
        {"type": "access-rule", "rule-number": 9, "name": "Cleanup rule", "enabled": True,
         "source": ["any"], "destination": ["any"], "service": ["any"], "action": "drop"},
    ]}
    tree = {"root_layer": "Network", "root_layers": ["Network"], "layers": [
        {"name": "Network", "depth": 0, "path": "Network", "display_prefix": "",
         "payload": payload}]}

    icmp = trace_access_tree(tree, "192.168.10.50", "192.168.20.10", "icmp",
                             resolve_service_query("8", "icmp", res(*objects)), "Network")
    assert icmp["result"] == "Accept"
    assert icmp["confidence"] == "exact"
    assert icmp["winner"]["rule"] == 7

    tcp = trace_access_tree(tree, "192.168.10.50", "192.168.20.10", "tcp",
                            resolve_service_query("443", "tcp", res(*objects)), "Network")
    assert tcp["result"] == "Drop"
    assert tcp["confidence"] == "exact", "an ICMP-only rule must not turn a TCP query unknown"
    assert tcp["winner"]["rule"] == 9


def test_the_ui_lets_someone_choose_icmp():
    from conftest import ui_source
    ui = ui_source()
    assert "<option>icmp</option>" in ui, "an ICMP rule cannot be traced from a tcp/udp-only selector"
