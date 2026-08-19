from conftest import app_source
MAIN=app_source()

def test_ui_exposes_trace_confidence():
    assert "confidence=d.access.confidence" in MAIN
    assert "UNVERIFIED" in MAIN

def test_parent_inline_colors_are_distinct():
    assert ".inline-parent-row:hover" in MAIN
    assert ".inline-child-row:hover" in MAIN
    assert ".pill.inline" in MAIN
