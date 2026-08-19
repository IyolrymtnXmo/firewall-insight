from app.inline_layers import aggregate_analyses

def test_inline_findings_are_counted_separately_and_still_in_total():
    tree = {
        "root_layers": ["Network"],
        "layers": [
            {"name": "Network", "depth": 0, "path": "Network"},
            {"name": "Inline-A", "depth": 1, "path": "Network → Inline-A"},
        ],
        "errors": [],
    }
    analyses = [
        {
            "summary": {"total_rules": 2},
            "rules": [
                {"rule": 1, "layer": "Network", "depth": 0, "enabled": True},
                {"rule": 2, "layer": "Network", "depth": 0, "enabled": True},
            ],
            "findings": {
                "shadowing": [{"rule": 2, "layer": "Network", "depth": 0}],
                "duplicates": [],
                "any_any_any_rule_numbers": [],
                "zero_hit_rule_numbers": [],
            },
        },
        {
            "summary": {"total_rules": 2},
            "rules": [
                {"rule": 1, "layer": "Inline-A", "depth": 1, "enabled": True},
                {"rule": 2, "layer": "Inline-A", "depth": 1, "enabled": True},
            ],
            "findings": {
                "shadowing": [{"rule": 2, "layer": "Inline-A", "depth": 1}],
                "duplicates": [{"members": [], "layer": "Inline-A", "depth": 1}],
                "any_any_any_rule_numbers": [1],
                "zero_hit_rule_numbers": [],
            },
        },
    ]
    result = aggregate_analyses(tree, analyses)
    s = result["summary"]

    assert s["potential_shadowed_or_redundant"] == 2
    assert s["inline_shadow_findings"] == 1
    assert s["top_level_shadow_findings"] == 1
    assert s["inline_duplicate_groups"] == 1
    assert s["inline_any_any_any_rules"] == 1
