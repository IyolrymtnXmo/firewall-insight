from conftest import app_source
from app.inline_layers import aggregate_analyses

MAIN = app_source()

def test_access_ui_is_package_first():
    assert "/api/package-analyze?package=" in MAIN
    assert "/api/package-policy-browser?package=" in MAIN
    assert "Select a Policy Package first." in MAIN

def test_top_level_count_is_not_inline_sum():
    tree = {
        "root_layers": ["Policy Network"],
        "layers": [
            {"name": "Policy Network", "path": "Policy Network", "depth": 0},
            {"name": "Inline A", "path": "Policy Network → Inline A", "depth": 1},
        ],
        "errors": [],
    }
    analyses = [
        {
            "summary": {"total_rules": 132},
            "findings": {"shadowing": [], "duplicates": [], "any_any_any_rule_numbers": [], "zero_hit_rule_numbers": []},
            "rules": [{"rule": i, "layer": "Policy Network", "enabled": True} for i in range(1,133)],
        },
        {
            "summary": {"total_rules": 20},
            "findings": {"shadowing": [], "duplicates": [], "any_any_any_rule_numbers": [], "zero_hit_rule_numbers": []},
            "rules": [{"rule": i, "layer": "Inline A", "enabled": True} for i in range(1,21)],
        },
    ]
    out = aggregate_analyses(tree, analyses)
    assert out["summary"]["total_rules"] == 132
    assert out["summary"]["inline_rules"] == 20
    assert out["summary"]["analyzed_rules"] == 152
