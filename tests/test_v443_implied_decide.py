"""
v4.43 - one service implied rule is decided by position instead of demoted.

Gateway order (R82 Security Management guide, "Implied rules"):
implied First -> explicit rules except the last -> implied Before Last ->
the last explicit rule -> implied Last -> implicit cleanup.

Only echo-request (ICMP 8), DNS over UDP/TCP 53 and RIP (UDP 520) are
decided, and only when no other implied rule can touch the connection.
"""
from app import implied
from app.traffic import trace_access_tree

OBJS = [
    {"uid": "any", "name": "Any", "type": "CpmiAnyObject"},
    {"uid": "accept", "name": "Accept", "type": "RulebaseAction"},
    {"uid": "drop", "name": "Drop", "type": "RulebaseAction"},
    {"uid": "n10", "name": "Net10", "type": "network", "subnet4": "192.168.10.0", "mask-length4": 24},
    {"uid": "web", "name": "Web", "type": "host", "ipv4-address": "10.0.0.80"},
    {"uid": "https", "name": "https", "type": "service-tcp", "port": "443"},
    {"uid": "echo", "name": "echo-request", "type": "service-icmp", "icmp-type": 8},
]
GATEWAYS = [{"uid": "gw", "name": "GW", "type": "simple-gateway", "ipv4-address": "172.16.0.1"}]


def rule(n, src, dst, svc, action):
    return {"type": "access-rule", "rule-number": n, "name": f"r{n}", "enabled": True,
            "source": [src], "destination": [dst], "service": [svc], "vpn": [], "action": action}


def tree(rules):
    pl = {"rulebase": rules, "objects-dictionary": OBJS}
    return {"root_layer": "L", "root_layers": ["L"],
            "layers": [{"name": "L", "depth": 0, "path": "L", "display_prefix": "", "payload": pl}]}


def q(proto, port):
    return {"atoms": [(proto, port, port)], "protocol": proto, "port": port, "display": f"{proto}/{port}"}


def ctx(position, key="accept-icmp-requests", **more):
    return implied.build_context({"firewall": {key: True, key + "-position": position, **more}}, GATEWAYS)


EXPLICIT_ICMP_DROP = [rule(1, "n10", "web", "echo", "drop"), rule(2, "n10", "web", "https", "accept"),
                      rule(3, "any", "any", "any", "drop")]


def run(rules, src, dst, proto, port, c):
    return trace_access_tree(tree(rules), src, dst, proto, q(proto, port), "L", implied=c)


def test_first_beats_an_explicit_drop():
    out = run(EXPLICIT_ICMP_DROP, "192.168.10.5", "10.0.0.80", "icmp", 8, ctx("first"))
    assert out["decided_by"] == "implied" and out["result"] == "Accept" and out["confidence"] == "exact"
    assert out["winner"]["implied_rule"] == "accept-icmp-requests"


def test_before_last_loses_to_an_earlier_explicit_rule():
    out = run(EXPLICIT_ICMP_DROP, "192.168.10.5", "10.0.0.80", "icmp", 8, ctx("before last"))
    assert out["confidence"] == "exact" and out["winner"]["rule"] == 1
    assert out["implied_rules"]["state"] == "resolved" and out["gateway_final"] is True


def test_before_last_beats_the_last_explicit_rule():
    out = run(EXPLICIT_ICMP_DROP, "10.9.9.9", "10.8.8.8", "icmp", 8, ctx("before last"))
    assert out["decided_by"] == "implied" and out["result"] == "Accept"


def test_last_loses_to_any_explicit_match_including_cleanup():
    out = run(EXPLICIT_ICMP_DROP, "10.9.9.9", "10.8.8.8", "icmp", 8, ctx("last"))
    assert out["winner"]["rule"] == 3 and out["result"] == "Drop" and out["confidence"] == "exact"


def test_last_decides_when_no_explicit_rule_matches():
    only = [rule(1, "n10", "web", "https", "accept")]
    out = run(only, "10.9.9.9", "10.8.8.8", "icmp", 8, ctx("last"))
    assert out["decided_by"] == "implied"


def test_unknown_position_is_still_only_demoted():
    c = implied.build_context({"firewall": {"accept-icmp-requests": True}}, GATEWAYS)
    out = run(EXPLICIT_ICMP_DROP, "10.9.9.9", "10.8.8.8", "icmp", 8, c)
    assert out["confidence"] != "exact" and "decided_by" not in out


def test_a_gateway_endpoint_is_never_decided():
    out = run(EXPLICIT_ICMP_DROP, "10.9.9.9", "172.16.0.1", "icmp", 8, ctx("first"))
    assert out["confidence"] != "exact" and "decided_by" not in out


def test_an_earlier_uncertain_rule_keeps_before_last_undecided():
    objs_rules = [rule(1, "zone", "any", "any", "drop"), rule(2, "any", "any", "any", "drop")]
    OBJS.append({"uid": "zone", "name": "Z", "type": "security-zone"})
    try:
        out = run(objs_rules, "10.9.9.9", "10.8.8.8", "icmp", 8, ctx("before last"))
        assert out["confidence"] != "exact" and "decided_by" not in out
    finally:
        OBJS.pop()


def test_dns_udp_decided_tcp_53_with_only_udp_rule_untouched():
    c = ctx("first", key="accept-domain-name-over-udp")
    assert run(EXPLICIT_ICMP_DROP, "10.9.9.9", "10.8.8.8", "udp", 53, c)["decided_by"] == "implied"
    out = run(EXPLICIT_ICMP_DROP, "10.9.9.9", "10.8.8.8", "tcp", 53, c)
    assert out["implied_rules"]["state"] == "clear" and out["winner"]["rule"] == 3


def test_two_ordered_layers_are_never_decided():
    t = tree(EXPLICIT_ICMP_DROP)
    t["root_layers"] = ["L", "M"]
    out = trace_access_tree(t, "10.9.9.9", "10.8.8.8", "icmp", q("icmp", 8), "L", implied=ctx("first"))
    assert "decided_by" not in out and out["gateway_final"] is False
