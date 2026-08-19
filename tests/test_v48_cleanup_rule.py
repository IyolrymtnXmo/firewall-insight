"""
v4.8 regression: a trailing Any/Any/Any Drop rule is the layer cleanup rule.

Reproduces the false positive found against a live lab Management Server
(API 2.0.1): package "Standard" reported any_any_any_rules = 1, and the
flagged rule was the implicit-deny "Cleanup rule" (Any/Any/Any/Drop) that
every Check Point policy is supposed to have. That cost 8 points of
optimization score for a policy with nothing wrong with it.
"""

from app.analyzer import analyze_rulebase, is_cleanup_rule
from app.inline_layers import aggregate_analyses

OBJECTS = [
    {"uid": "any", "name": "Any", "type": "CpmiAnyObject"},
    {"uid": "net", "name": "LAB-VLAN20", "type": "network",
     "subnet4": "192.168.20.0", "mask-length4": 24},
    {"uid": "https", "name": "https", "type": "service-tcp", "port": "443"},
    {"uid": "accept", "name": "Accept", "type": "RulebaseAction"},
    {"uid": "drop", "name": "Drop", "type": "RulebaseAction"},
]


def _payload(last_action="drop", last_name="Cleanup rule"):
    return {
        "objects-dictionary": OBJECTS,
        "rulebase": [
            {"type": "access-rule", "rule-number": 1, "enabled": True,
             "source": ["net"], "destination": ["any"], "service": ["https"],
             "vpn": [], "action": "accept"},
            {"type": "access-rule", "rule-number": 2, "enabled": True,
             "name": last_name,
             "source": ["any"], "destination": ["any"], "service": ["any"],
             "vpn": [], "action": last_action},
        ],
    }


def test_trailing_any_any_any_drop_is_not_an_any_finding():
    result = analyze_rulebase(_payload())
    assert result["summary"]["any_any_any_rules"] == 0
    assert result["summary"]["cleanup_rules"] == 1
    assert result["findings"]["cleanup_rule_numbers"] == [2]
    assert result["findings"]["any_any_any_rule_numbers"] == []


def test_cleanup_rule_no_longer_costs_optimization_score():
    """The whole point of the fix: a healthy policy should score 100."""
    assert analyze_rulebase(_payload())["summary"]["optimization_score"] == 100


def test_trailing_any_any_any_accept_is_still_a_real_finding():
    """An Any/Any/Any *Accept* at the end is a genuine security problem."""
    result = analyze_rulebase(_payload(last_action="accept", last_name="Allow all"))
    assert result["summary"]["any_any_any_rules"] == 1
    assert result["summary"]["cleanup_rules"] == 0
    assert result["summary"]["optimization_score"] == 92


def test_any_any_any_drop_in_the_middle_is_still_a_finding():
    """Only the LAST rule can be the cleanup rule - position matters."""
    payload = _payload()
    payload["rulebase"].append(
        {"type": "access-rule", "rule-number": 3, "enabled": True,
         "source": ["net"], "destination": ["any"], "service": ["https"],
         "vpn": [], "action": "accept"}
    )
    result = analyze_rulebase(payload)
    assert result["findings"]["any_any_any_rule_numbers"] == [2]
    assert result["summary"]["cleanup_rules"] == 0


def test_cleanup_detection_ignores_rule_name():
    """Named 'Final deny' in another language/convention - still detected."""
    result = analyze_rulebase(_payload(last_name="ปฏิเสธทั้งหมด"))
    assert result["summary"]["cleanup_rules"] == 1


def test_is_cleanup_rule_is_importable_for_reuse():
    assert callable(is_cleanup_rule)


def test_aggregate_reports_cleanup_rules_across_layers():
    tree = {"root_layers": ["Network"], "layers": [
        {"name": "Network", "path": "Network", "depth": 0,
         "parent_layer": None, "parent_rule": None, "display_prefix": "",
         "rule_count": 2},
    ]}
    analysis = analyze_rulebase(_payload())
    for row in analysis["rules"]:
        row["layer"] = "Network"
        row["display_rule"] = str(row["rule"])
    merged = aggregate_analyses(tree, [analysis])
    assert merged["summary"]["cleanup_rules"] == 1
    assert merged["summary"]["any_any_any_rules"] == 0
    assert merged["findings"]["cleanup_rules"][0]["rule"] == 2


def test_ui_explains_excluded_cleanup_rules():
    from pathlib import Path
    src = Path("app/main.py").read_text(encoding="utf-8")
    assert "function cleanupNote(d)" in src
    assert "cleanup_rules" in src
    assert "+cleanupNote(d);" in src
