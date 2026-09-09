from conftest import app_source
MAIN=app_source()

def test_traffic_ui_shows_matched_policy_path():
    assert "Matched Policy Path" in MAIN
    assert "Top-level → Inline Layer → Final Action" in MAIN
    assert "w.display_rule||w.rule" in MAIN

def test_inline_rows_are_marked_as_structure_not_as_a_verdict():
    """An Inline Layer badge must not borrow an allow/deny/unproven colour.

    Before v4.30 this pinned one literal blue. What it was actually protecting
    is that a rule's *position in the layer tree* is structural information and
    must not be dressed in one of the three colours the app reserves for
    verdicts, or a reader learns to read hierarchy as risk.
    """
    assert ".pill.inline" in MAIN
    inline_rule = MAIN.split(".pill.inline")[1].split("}")[0]
    for verdict in ("--good", "--bad", "--warn"):
        assert verdict not in inline_rule, f".pill.inline must not use {verdict}"
    assert "--muted" in inline_rule or "--line-str" in inline_rule
