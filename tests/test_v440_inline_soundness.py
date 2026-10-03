"""
v4.40 - an Inline Layer must not turn an uncertain path into a definite one.

Found by the E2b experiment (experiments/inline_soundness): on synthetic
policies with Inline Layers and an R82-style gateway model, v4.39 reported a
definite result that the gateway would not produce in 5-8 % of connections.
Three shapes caused it; each has a test here.

  1. an earlier rule is uncertain, a later Inline Layer parent matches exactly
     and its child matches exactly -> v4.39 said "exact"
  2. the parent matches exactly, but inside the child an uncertain rule comes
     before the matching one -> v4.39 said "No final matching rule", exact
  3. the parent is uncertain and no child rule matches -> v4.39 skipped the
     parent and declared a later rule (often Cleanup) exact, although at the
     gateway the child layer's implicit cleanup would have decided
"""

from app.traffic import trace_access_tree

ANY = {"uid": "any", "name": "Any", "type": "CpmiAnyObject"}
ACCEPT = {"uid": "accept", "name": "Accept", "type": "RulebaseAction"}
DROP = {"uid": "drop", "name": "Drop", "type": "RulebaseAction"}
INLINE = {"uid": "inline", "name": "Inline Layer", "type": "RulebaseAction"}
NET10 = {"uid": "n10", "name": "VLAN10", "type": "network", "subnet4": "192.168.10.0", "mask-length4": 24}
WEB = {"uid": "web", "name": "Web", "type": "host", "ipv4-address": "10.0.0.80"}
HTTPS = {"uid": "https", "name": "https", "type": "service-tcp", "port": "443"}
ZONE = {"uid": "zone", "name": "InternalZone", "type": "security-zone"}
OBJS = [ANY, ACCEPT, DROP, INLINE, NET10, WEB, HTTPS, ZONE]


def rule(n, src, dst, svc, action, inline=None):
    r = {"type": "access-rule", "rule-number": n, "name": f"r{n}", "enabled": True,
         "source": [src], "destination": [dst], "service": [svc], "vpn": [], "action": action}
    if inline:
        r["inline-layer"] = inline
    return r


def tree(root_rules, child_rules):
    return {
        "root_layer": "L", "root_layers": ["L"],
        "layers": [
            {"name": "L", "depth": 0, "path": "L", "display_prefix": "",
             "payload": {"rulebase": root_rules, "objects-dictionary": OBJS}},
            {"name": "C", "depth": 1, "path": "L > C", "display_prefix": "2",
             "parent_layer": "L", "parent_rule": 2,
             "payload": {"rulebase": child_rules, "objects-dictionary": OBJS}},
        ],
    }


def trace(t):
    return trace_access_tree(t, "192.168.10.5", "10.0.0.80", "tcp",
                             {"atoms": [("tcp", 443, 443)], "protocol": "tcp", "port": 443,
                              "display": "tcp/443"}, "L")


def test_an_earlier_uncertain_rule_blocks_a_later_inline_path():
    t = tree([rule(1, "zone", "any", "any", "drop"),
              rule(2, "n10", "any", "any", "inline", inline="C"),
              rule(3, "any", "any", "any", "drop")],
             [rule(1, "n10", "web", "https", "accept")])
    out = trace(t)
    assert out["confidence"] != "exact", out
    assert out["result"] == "UNVERIFIED"
    assert out["possible_winner"]["rule"] == 1


def test_an_uncertain_child_rule_is_not_reported_as_no_final_match():
    t = tree([rule(1, "web", "any", "any", "drop"),
              rule(2, "n10", "any", "any", "inline", inline="C"),
              rule(3, "any", "any", "any", "drop")],
             [rule(1, "zone", "any", "any", "drop"),
              rule(2, "n10", "web", "https", "accept")])
    out = trace(t)
    assert not (out["result"] == "No final matching rule" and out["confidence"] == "exact"), out
    assert out["confidence"] == "unknown"


def test_an_uncertain_parent_without_a_child_match_blocks_later_rules():
    t = tree([rule(1, "web", "any", "any", "drop"),
              rule(2, "zone", "any", "any", "inline", inline="C"),
              rule(3, "any", "any", "any", "drop")],
             [rule(1, "web", "web", "https", "accept")])
    out = trace(t)
    assert out["confidence"] != "exact", out
    assert out["result"] == "UNVERIFIED"


def test_an_exact_path_through_an_inline_layer_is_still_exact():
    t = tree([rule(1, "web", "any", "any", "drop"),
              rule(2, "n10", "any", "any", "inline", inline="C"),
              rule(3, "any", "any", "any", "drop")],
             [rule(1, "n10", "web", "https", "accept")])
    out = trace(t)
    assert out["matched"] and out["confidence"] == "exact"
    assert out["winner"]["display_rule"] == "2.1"


def test_an_exact_parent_with_no_child_match_names_the_child_cleanup():
    t = tree([rule(1, "web", "any", "any", "drop"),
              rule(2, "n10", "any", "any", "inline", inline="C"),
              rule(3, "any", "any", "any", "accept")],
             [rule(1, "web", "web", "https", "accept")])
    out = trace(t)
    assert out["result"] == "No final matching rule" and out["confidence"] == "exact"
    assert "implicit cleanup" in out["reason"]
