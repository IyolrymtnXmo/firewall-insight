from pathlib import Path

def test_access_policy_summary_is_raw_access_control_only():
    src = Path("app/main.py").read_text(encoding="utf-8")
    assert "['Policy Type','Access Control']" in src
    assert "['Optimizer Analysis','Not Applied']" not in src

def test_nat_no_translation_drilldown_renderer_present():
    src = Path("app/main.py").read_text(encoding="utf-8")
    assert "function renderNatSpecialViews(data)" in src
    assert "possible_no_translation_rule_numbers" in src
    assert "function showNatTab(tab,btn)" in src
    assert "nat-notrans-view" in src

def test_nat_analysis_populates_special_views():
    src = Path("app/main.py").read_text(encoding="utf-8")
    run = src.split("async function runNat()",1)[1].split("\nfunction ",1)[0]
    assert "renderNatSpecialViews(natData)" in run
