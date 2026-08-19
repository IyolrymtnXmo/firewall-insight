from pathlib import Path

def test_nat_show_hits_removed():
    source = Path("app/checkpoint.py").read_text(encoding="utf-8")
    nat = source.split("async def show_nat_rulebase",1)[1]
    assert '"show-hits"' not in nat

def test_drilldown_and_icons_present():
    source = Path("app/main.py").read_text(encoding="utf-8")
    assert "function drillTo(" in source
    assert "function topoIcon(" in source
    assert "role==='gateway'" in source
    assert "role==='management'" in source
