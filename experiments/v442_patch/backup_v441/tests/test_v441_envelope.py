"""
v4.41 - the tool enforces its own supported-policy envelope.

v4.40 listed Time, Content, Install On, several Ordered Layers and implied
rules as preconditions the user had to check. A review pointed out that a
requirement of the tool is "never present what it does not know as known",
so the tool now checks those preconditions itself:

  * a rule narrowed by Time / Content / Install On is never a proven match
  * such a rule never counts as the covering rule of a shadowing pair
  * a package with several Ordered Layers never yields a gateway-final answer
  * every trace says that implied rules are outside the model
"""

from app.analyzer import analyze_rulebase
from app.traffic import trace_access_tree

ANY = {"uid": "any", "name": "Any", "type": "CpmiAnyObject"}
PT = {"uid": "pt", "name": "Policy Targets", "type": "Global"}
GWA = {"uid": "gwa", "name": "GW-A", "type": "simple-gateway"}
WORK = {"uid": "work", "name": "Work-Hours", "type": "time"}
PII = {"uid": "pii", "name": "PII", "type": "data-type"}
ACCEPT = {"uid": "accept", "name": "Accept", "type": "RulebaseAction"}
DROP = {"uid": "drop", "name": "Drop", "type": "RulebaseAction"}
NET10 = {"uid": "n10", "name": "VLAN10", "type": "network", "subnet4": "192.168.10.0", "mask-length4": 24}
WEB = {"uid": "web", "name": "Web", "type": "host", "ipv4-address": "10.0.0.80"}
HTTPS = {"uid": "https", "name": "https", "type": "service-tcp", "port": "443"}
OBJS = [ANY, PT, GWA, WORK, PII, ACCEPT, DROP, NET10, WEB, HTTPS]


def rule(n, src, dst, svc, action, time="any", content="any", install="pt", **extra):
    return {"type": "access-rule", "rule-number": n, "name": f"r{n}", "enabled": True,
            "source": [src], "destination": [dst], "service": [svc], "vpn": [], "action": action,
            "time": [time], "content": [content], "install-on": [install], **extra}


def tree(rules, roots=("L",)):
    layers = [{"name": r, "depth": 0, "path": r, "display_prefix": "",
               "payload": {"rulebase": rules, "objects-dictionary": OBJS}} for r in roots]
    return {"root_layer": roots[0], "root_layers": list(roots), "layers": layers}


def trace(t):
    return trace_access_tree(t, "192.168.10.5", "10.0.0.80", "tcp",
                             {"atoms": [("tcp", 443, 443)], "protocol": "tcp", "port": 443,
                              "display": "tcp/443"}, "L")


def test_defaults_still_give_an_exact_answer():
    out = trace(tree([rule(1, "n10", "web", "https", "accept"), rule(2, "any", "any", "any", "drop")]))
    assert out["matched"] and out["confidence"] == "exact" and out["winner"]["rule"] == 1
    assert out["gateway_final"] is True


def test_a_time_window_blocks_a_definite_answer():
    out = trace(tree([rule(1, "n10", "web", "https", "accept", time="work"),
                      rule(2, "any", "any", "any", "drop")]))
    assert out["confidence"] != "exact" and out["result"] == "UNVERIFIED"
    assert out["possible_winner"]["rule"] == 1


def test_content_and_install_on_block_a_definite_answer():
    for kw in ({"content": "pii"}, {"install": "gwa"}, {"content-negate": True}):
        out = trace(tree([rule(1, "n10", "web", "https", "accept", **kw),
                          rule(2, "any", "any", "any", "drop")]))
        assert out["result"] == "UNVERIFIED", kw


def test_an_unmodelled_column_never_turns_a_miss_into_unknown():
    # rule 1 cannot match on its source, whatever its time window says
    out = trace(tree([rule(1, "web", "web", "https", "drop", time="work"),
                      rule(2, "n10", "web", "https", "accept")]))
    assert out["matched"] and out["confidence"] == "exact" and out["winner"]["rule"] == 2


def test_several_ordered_layers_never_give_a_gateway_final_answer():
    out = trace(tree([rule(1, "n10", "web", "https", "accept")], roots=("L", "L2")))
    assert out["confidence"] != "exact" and out["gateway_final"] is False
    assert "Ordered Layers" in out["reason"]


def test_every_trace_carries_the_implied_rules_note():
    out = trace(tree([rule(1, "n10", "web", "https", "accept")]))
    assert any("Implied rules" in n for n in out["scope_notes"])


def _shadowed(rules):
    a = analyze_rulebase({"rulebase": rules, "objects-dictionary": OBJS})
    return {s["rule"] for s in a["findings"]["shadowing"]}


def test_a_time_limited_rule_cannot_shadow_a_later_one():
    assert _shadowed([rule(1, "n10", "any", "any", "drop", time="work"),
                      rule(2, "n10", "web", "https", "accept")]) == set()


def test_an_install_on_limited_rule_cannot_shadow_a_later_one():
    assert _shadowed([rule(1, "n10", "any", "any", "drop", install="gwa"),
                      rule(2, "n10", "web", "https", "accept")]) == set()


def test_a_default_rule_still_shadows_a_restricted_later_one():
    assert _shadowed([rule(1, "n10", "any", "any", "drop"),
                      rule(2, "n10", "web", "https", "accept", time="work")]) == {2}
