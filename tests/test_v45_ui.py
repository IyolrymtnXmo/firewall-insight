from pathlib import Path
MAIN=Path("app/main.py").read_text(encoding="utf-8")

def test_traffic_ui_shows_matched_policy_path():
    assert "Matched Policy Path" in MAIN
    assert "Top-level → Inline Layer → Final Action" in MAIN
    assert "w.display_rule||w.rule" in MAIN

def test_inline_rows_use_blue_neutral_style():
    assert ".pill.inline" in MAIN
    assert "rgba(96,165,250" in MAIN
