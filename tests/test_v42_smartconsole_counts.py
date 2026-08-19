from app.inline_layers import aggregate_browser

def test_browser_count_matches_root_rulebase_not_root_plus_inline():
    tree = {
        "root_layers": ["NSTH_POLICY Network"],
        "layers": [
            {"name": "NSTH_POLICY Network", "path": "NSTH_POLICY Network", "depth": 0},
            {"name": "Inline-Web", "path": "NSTH_POLICY Network → Inline-Web", "depth": 1, "parent_rule": 49},
        ],
        "errors": [],
    }
    browsed = [
        {"total_rules": 132, "rules": [{"rule": i} for i in range(1, 133)]},
        {"total_rules": 30, "rules": [{"rule": i} for i in range(1, 31)]},
    ]
    result = aggregate_browser(tree, browsed)
    assert result["total_rules"] == 132
    assert result["top_level_rules"] == 132
    assert result["inline_rules"] == 30
    assert result["visible_rules"] == 162
