"""
v4.42 - implied rules stop a result from being reported as definite.

Implied rules come from Global Properties and are enforced First, Before Last
or Last around the explicit rules. `show-access-rulebase` does not return
them. Up to v4.41 a trace carried a warning about them and still said
"confidence: exact". These tests pin the replacement: the result itself is
demoted whenever an implied rule could apply, or when that cannot be decided.
"""
import asyncio
import re
from pathlib import Path

from app import implied
from app.traffic import trace_access_tree

ROOT = Path(__file__).resolve().parent.parent

OBJS = [
    {"uid": "any", "name": "Any", "type": "CpmiAnyObject"},
    {"uid": "accept", "name": "Accept", "type": "RulebaseAction"},
    {"uid": "drop", "name": "Drop", "type": "RulebaseAction"},
    {"uid": "n10", "name": "Net10", "type": "network", "subnet4": "192.168.10.0", "mask-length4": 24},
    {"uid": "web", "name": "Web", "type": "host", "ipv4-address": "10.0.0.80"},
    {"uid": "https", "name": "https", "type": "service-tcp", "port": "443"},
]

GATEWAYS = [
    {"uid": "gw", "name": "External-GW01", "type": "cluster-member", "ipv4-address": "172.16.0.1",
     "interfaces": [{"name": "eth1", "ipv4-address": "192.168.10.254"}]},
    {"uid": "mgmt", "name": "CP-MGMT-01", "type": "checkpoint-host", "ipv4-address": "172.16.0.10"},
]


def rule(n, src, dst, svc, action):
    return {"type": "access-rule", "rule-number": n, "name": f"r{n}", "enabled": True,
            "source": [src], "destination": [dst], "service": [svc], "vpn": [], "action": action}


def tree(rules):
    pl = {"rulebase": rules, "objects-dictionary": OBJS}
    return {"root_layer": "L", "root_layers": ["L"],
            "layers": [{"name": "L", "depth": 0, "path": "L", "display_prefix": "", "payload": pl}]}


POLICY = [rule(1, "n10", "web", "https", "accept"), rule(2, "any", "any", "any", "drop")]


def q(proto, port):
    return {"atoms": [(proto, port, port)], "protocol": proto, "port": port, "display": f"{proto}/{port}"}


def props(**firewall):
    return {"firewall": firewall}


def trace(src, dst, proto, port, ctx):
    return trace_access_tree(tree(POLICY), src, dst, proto, q(proto, port), "L", implied=ctx)


# ---- reading the two API answers -------------------------------------------

def test_only_switched_on_rules_are_collected_and_positions_are_kept():
    ctx = implied.build_context(props(**{
        "accept-control-connections": True,
        "accept-icmp-requests": True, "accept-icmp-requests-position": "before last",
        "accept-rip": False, "log-implied-rules": True}), GATEWAYS)
    assert sorted(ctx["enabled"]) == ["accept-control-connections", "accept-icmp-requests"]
    assert ctx["positions"]["accept-icmp-requests"] == "before last"
    assert not ctx["unrecognised"] and not ctx["problems"]


def test_device_addresses_include_interfaces():
    ctx = implied.build_context(props(), GATEWAYS)
    text = {int(__import__("ipaddress").ip_address(a)) for a in
            ("172.16.0.1", "192.168.10.254", "172.16.0.10")}
    assert text <= {a for a, _v in ctx["addresses"]}


# ---- clear: the explicit result stands -------------------------------------

def test_a_flow_no_implied_rule_can_touch_stays_exact():
    ctx = implied.build_context(props(**{"accept-control-connections": True}), GATEWAYS)
    out = trace("192.168.10.5", "10.0.0.80", "tcp", 443, ctx)
    assert out["matched"] and out["confidence"] == "exact" and out["gateway_final"] is True
    assert out["implied_rules"]["state"] == "clear"


# ---- possible: demoted ------------------------------------------------------

def test_a_flow_from_a_gateway_address_is_not_exact():
    """Rule 2 says Drop. 'Accept outgoing packets originating from gateway' may say otherwise."""
    ctx = implied.build_context(props(**{"accept-outgoing-packets-originating-from-gw": True}), GATEWAYS)
    out = trace("172.16.0.1", "8.8.8.8", "tcp", 443, ctx)
    assert out["confidence"] == "inferred" and out["gateway_final"] is False
    assert out["implied_rules"]["state"] == "possible"
    assert "accept-outgoing-packets-originating-from-gw" in out["implied_rules"]["rules"]


def test_a_gateway_endpoint_is_demoted_even_with_every_checkbox_off():
    """Blades add implied rules for the gateway that have no checkbox."""
    ctx = implied.build_context(props(), GATEWAYS)
    out = trace("192.168.10.5", "192.168.10.254", "tcp", 443, ctx)
    assert out["confidence"] != "exact" and out["gateway_final"] is False


def test_icmp_is_demoted_only_when_the_icmp_implied_rule_is_on():
    on = implied.build_context(props(**{"accept-icmp-requests": True,
                                        "accept-icmp-requests-position": "first"}), GATEWAYS)
    off = implied.build_context(props(**{"accept-icmp-requests": False}), GATEWAYS)
    # v4.43: echo-request with the rule placed First is now decided by the
    # implied rule (tests/test_v443_implied_decide.py); a request type outside
    # the modelled set is still only demoted.
    assert trace("192.168.10.5", "10.0.0.80", "icmp", 13, on)["confidence"] == "inferred"
    decided = trace("192.168.10.5", "10.0.0.80", "icmp", 8, on)
    assert decided["decided_by"] == "implied" and decided["result"] == "Accept"
    assert trace("192.168.10.5", "10.0.0.80", "icmp", 8, off)["confidence"] == "exact"


def test_dns_and_rip_are_matched_by_service():
    ctx = implied.build_context(props(**{"accept-domain-name-over-udp": True, "accept-rip": True}), GATEWAYS)
    assert trace("192.168.10.5", "10.9.9.9", "udp", 53, ctx)["confidence"] == "inferred"
    assert trace("192.168.10.5", "10.9.9.9", "udp", 520, ctx)["confidence"] == "inferred"
    assert trace("192.168.10.5", "10.9.9.9", "tcp", 53, ctx)["confidence"] == "exact"
    assert trace("192.168.10.5", "10.9.9.9", "udp", 54, ctx)["confidence"] == "exact"


def test_no_matching_rule_becomes_unverified_not_a_definite_miss():
    ctx = implied.build_context(props(**{"accept-icmp-requests": True}), GATEWAYS)
    only = [rule(1, "n10", "web", "https", "accept")]
    out = trace_access_tree(tree(only), "10.1.1.1", "10.2.2.2", "icmp", q("icmp", 8), "L", implied=ctx)
    assert out["result"] == "UNVERIFIED" and out["confidence"] == "unknown"


# ---- unread: everything is demoted -----------------------------------------

def test_unreadable_global_properties_demote_every_trace():
    ctx = implied.build_context(None, GATEWAYS)
    out = trace("192.168.10.5", "10.0.0.80", "tcp", 443, ctx)
    assert out["confidence"] == "inferred" and out["implied_rules"]["state"] == "unread"


def test_an_unreadable_gateway_list_demotes_every_trace():
    ctx = implied.build_context(props(), None)
    assert trace("192.168.10.5", "10.0.0.80", "tcp", 443, ctx)["implied_rules"]["state"] == "unread"


def test_a_switched_on_rule_this_version_does_not_know_demotes_every_trace():
    ctx = implied.build_context(props(**{"accept-something-added-in-a-later-release": True}), GATEWAYS)
    out = trace("192.168.10.5", "10.0.0.80", "tcp", 443, ctx)
    assert out["implied_rules"]["state"] == "unread" and out["confidence"] != "exact"


def test_a_gateway_with_a_dynamic_address_demotes_every_trace():
    daip = GATEWAYS + [{"uid": "d", "name": "Branch-DAIP", "type": "simple-gateway", "dynamic-ip": True}]
    ctx = implied.build_context(props(), daip)
    assert trace("192.168.10.5", "10.0.0.80", "tcp", 443, ctx)["confidence"] != "exact"


# ---- a demotion never invents certainty ------------------------------------

def test_an_already_uncertain_result_is_left_uncertain():
    ctx = implied.build_context(props(**{"accept-icmp-requests": True}), GATEWAYS)
    objs = OBJS + [{"uid": "z", "name": "Zone", "type": "security-zone"}]
    pl = {"rulebase": [rule(1, "z", "web", "any", "accept"), rule(2, "any", "any", "any", "drop")],
          "objects-dictionary": objs}
    t = {"root_layer": "L", "root_layers": ["L"],
         "layers": [{"name": "L", "depth": 0, "path": "L", "display_prefix": "", "payload": pl}]}
    out = trace_access_tree(t, "192.168.10.5", "10.0.0.80", "icmp", q("icmp", 8), "L", implied=ctx)
    assert out["result"] == "UNVERIFIED" and out["confidence"] == "unknown"


# ---- the paths a person sees must pass a context ---------------------------

def test_every_reporting_caller_passes_an_implied_context():
    for rel in ("app/api/traffic.py", "tools/acceptance.py"):
        text = (ROOT / rel).read_text(encoding="utf-8")
        calls = re.findall(r"trace_access_tree\((?:[^()]|\([^()]*\))*\)", text)
        assert calls, rel
        for call in calls:
            assert "implied=" in call, f"{rel} calls the tracer without implied rules: {call[:80]}"


def test_global_properties_are_read_with_a_show_command():
    from app.checkpoint import CheckPointClient
    seen = []

    async def fake(self, command, payload=None):
        seen.append(command)
        return {"firewall": {}}

    c = CheckPointClient()
    original = CheckPointClient.call
    CheckPointClient.call = fake
    try:
        asyncio.run(c.show_global_properties())
    finally:
        CheckPointClient.call = original
    assert seen == ["show-global-properties"]
