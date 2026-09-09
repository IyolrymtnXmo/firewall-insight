from conftest import app_source
MAIN=app_source()

def test_traffic_ui_shows_matched_policy_path():
    assert "Matched Policy Path" in MAIN
    assert "Top-level → Inline Layer → Final Action" in MAIN
    assert "w.display_rule||w.rule" in MAIN

def test_inline_rows_are_marked_as_structure_not_as_a_verdict():
    """An Inline Layer badge must not borrow an allow/deny/unproven colour.

    Before v4.30 this pinned one literal blue. What it protects is that a
    rule's *position in the layer tree* is structural information, and must not
    be dressed in one of the colours the app reserves for verdicts - or readers
    learn to read hierarchy as risk.
    """
    assert ".pill.inline" in MAIN
    rule = MAIN.split(".pill.inline")[1].split("}")[0]
    for verdict in ("--good", "--bad", "--warn"):
        assert verdict not in rule, f".pill.inline must not use {verdict}"
    assert "--info" in rule or "--muted" in rule
