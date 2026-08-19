from app.inline_layers import aggregate_analyses, aggregate_browser, inline_ref


def test_inline_ref_dict_uid_or_name():
    assert inline_ref({"inline-layer": {"uid": "u1", "name": "Web Inline"}}, {}) == ("u1", "Web Inline")
    assert inline_ref({"inline-layer": "u1"}, {"u1": "Web Inline"}) == ("u1", "Web Inline")
    assert inline_ref({"inline-layer": "Web Inline"}, {}) == ("", "Web Inline")


def test_aggregate_analysis_counts_top_and_inline_rules():
    tree = {
        "layers": [
            {"name": "Network", "path": "Network", "depth": 0, "rule_count": 2},
            {"name": "Inline A", "path": "Network → Inline A", "depth": 1, "rule_count": 3, "parent_rule": 2},
        ],
        "errors": [],
    }
    analyses = [
        {
            "summary": {"total_rules": 2},
            "findings": {"shadowing": [], "duplicates": [], "any_any_any_rule_numbers": [], "zero_hit_rule_numbers": []},
            "rules": [{"rule": 1, "layer": "Network", "enabled": True}, {"rule": 2, "layer": "Network", "enabled": True}],
        },
        {
            "summary": {"total_rules": 3},
            "findings": {"shadowing": [], "duplicates": [], "any_any_any_rule_numbers": [], "zero_hit_rule_numbers": []},
            "rules": [
                {"rule": 1, "layer": "Inline A", "enabled": True},
                {"rule": 2, "layer": "Inline A", "enabled": True},
                {"rule": 3, "layer": "Inline A", "enabled": True},
            ],
        },
    ]
    out = aggregate_analyses(tree, analyses)
    assert out["summary"]["total_rules"] == 2
    assert out["summary"]["top_level_rules"] == 2
    assert out["summary"]["inline_rules"] == 3
    assert out["summary"]["analyzed_rules"] == 5
    assert out["summary"]["inline_layers"] == 1


def test_browser_aggregate_preserves_layer_context():
    tree = {
        "root_layer": "Network",
        "layers": [
            {"name": "Network", "path": "Network", "depth": 0, "rule_count": 1},
            {"name": "Inline A", "path": "Network → Inline A", "depth": 1, "rule_count": 1, "parent_rule": 10, "parent_layer": "Network"},
        ],
        "errors": [],
    }
    browsed = [
        {"total_rules": 1, "rules": [{"rule": 10}]},
        {"total_rules": 1, "rules": [{"rule": 1}]},
    ]
    out = aggregate_browser(tree, browsed)
    assert out["total_rules"] == 1
    assert out["inline_rules"] == 1
    assert out["visible_rules"] == 2
    assert out["inline_layers"] == 1
    assert out["rules"][1]["layer"] == "Inline A"
    assert out["rules"][1]["parent_rule"] == 10
