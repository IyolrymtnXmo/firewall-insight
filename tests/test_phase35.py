from pathlib import Path

def test_nat_rulebase_does_not_request_show_hits():
    source = Path("app/checkpoint.py").read_text(encoding="utf-8")
    block = source.split("async def show_nat_rulebase", 1)[1]
    assert '"show-hits": True' not in block

def test_settings_removed_from_ui():
    source = Path("app/main.py").read_text(encoding="utf-8")
    assert 'data-page="settings"' not in source
    assert '<section id="settings"' not in source
