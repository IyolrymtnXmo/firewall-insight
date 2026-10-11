"""v4.43 - Install On decided for a known traced gateway."""
from app.envelope import make_target
from app.traffic import trace_access_tree

OBJS = [
    {"uid": "any", "name": "Any", "type": "CpmiAnyObject"},
    {"uid": "accept", "name": "Accept", "type": "RulebaseAction"},
    {"uid": "drop", "name": "Drop", "type": "RulebaseAction"},
    {"uid": "pt", "name": "Policy Targets", "type": "Global"},
    {"uid": "gwa", "name": "GW-A", "type": "simple-gateway"},
    {"uid": "gwb", "name": "GW-B", "type": "simple-gateway"},
    {"uid": "grp", "name": "Some-Group", "type": "group"},
    {"uid": "work", "name": "Work-Hours", "type": "time"},
    {"uid": "n10", "name": "Net10", "type": "network", "subnet4": "10.0.0.0", "mask-length4": 8},
    {"uid": "https", "name": "https", "type": "service-tcp", "port": "443"},
]


def rule(n, inst, action="accept", time="any"):
    return {"type": "access-rule", "rule-number": n, "name": f"r{n}", "enabled": True,
            "source": ["n10"], "destination": ["n10"], "service": ["https"], "vpn": [],
            "action": action, "install-on": [inst], "time": [time], "content": ["any"]}


CLEAN = {"type": "access-rule", "rule-number": 9, "name": "Cleanup", "enabled": True, "source": ["any"],
         "destination": ["any"], "service": ["any"], "vpn": [], "action": "drop", "install-on": ["pt"]}


def run(rules, target):
    pl = {"rulebase": rules + [CLEAN], "objects-dictionary": OBJS}
    tree = {"root_layer": "L", "root_layers": ["L"],
            "layers": [{"name": "L", "depth": 0, "path": "L", "display_prefix": "", "payload": pl}]}
    q = {"atoms": [("tcp", 443, 443)], "protocol": "tcp", "port": 443, "display": "tcp/443"}
    return trace_access_tree(tree, "10.1.1.1", "10.2.2.2", "tcp", q, "L", target=target)


def test_rule_installed_on_the_traced_gateway_matches():
    out = run([rule(1, "gwa")], make_target("gwa", "GW-A"))
    assert out["confidence"] == "exact" and out["winner"]["rule"] == 1


def test_rule_installed_elsewhere_is_a_proven_miss():
    out = run([rule(1, "gwb")], make_target("gwa", "GW-A"))
    assert out["confidence"] == "exact" and out["winner"]["rule"] == 9


def test_name_match_is_enough():
    out = run([rule(1, "gwa")], make_target("", "GW-A"))
    assert out["winner"]["rule"] == 1


def test_unknown_target_keeps_the_v441_behaviour():
    out = run([rule(1, "gwb")], None)
    assert out["confidence"] == "unknown"


def test_a_group_in_install_on_stays_unknown():
    out = run([rule(1, "grp")], make_target("gwa", "GW-A"))
    assert out["confidence"] == "unknown"


def test_time_still_caps_a_rule_installed_here():
    out = run([rule(1, "gwa", time="work")], make_target("gwa", "GW-A"))
    assert out["confidence"] == "unknown"


def test_time_does_not_rescue_a_rule_installed_elsewhere():
    out = run([rule(1, "gwb", time="work")], make_target("gwa", "GW-A"))
    assert out["confidence"] == "exact" and out["winner"]["rule"] == 9
