from conftest import app_source
from pathlib import Path

MAIN = app_source()
CP = Path("app/checkpoint.py").read_text(encoding="utf-8")

def test_recursive_rulebase_api_present():
    assert "async def show_rulebase_tree" in CP
    assert "inline_ref(rule" in CP

def test_dashboard_breakdown_present():
    assert "top-level +" in MAIN
    assert "s.inline_rules" in MAIN
    assert "s.inline_layers" in MAIN

def test_analyze_results_show_layer_column():
    assert "<th>Layer</th><th>Rule</th><th>Covered By</th>" in MAIN

def test_raw_policy_searches_layer_context():
    assert "r.layer,r.layer_path,r.parent_rule" in MAIN
