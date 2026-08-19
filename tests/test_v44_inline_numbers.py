from app.inline_layers import annotate_analysis

def test_inline_display_rule_parent_30():
    node = {
        "name":"HarmonySASE",
        "path":"NSTH_POLICY Network → HarmonySASE",
        "depth":1,
        "parent_rule":30,
        "display_prefix":"30",
    }
    result = {
        "rules":[{"rule":1},{"rule":2},{"rule":3}],
        "findings":{"shadowing":[],"duplicates":[]},
    }
    out = annotate_analysis(result,node)
    assert [r["display_rule"] for r in out["rules"]] == ["30.1","30.2","30.3"]

def test_nested_inline_display_rule():
    node = {
        "name":"Nested",
        "path":"Network → A → Nested",
        "depth":2,
        "parent_rule":2,
        "display_prefix":"30.2",
    }
    result = {
        "rules":[{"rule":1}],
        "findings":{"shadowing":[],"duplicates":[]},
    }
    out = annotate_analysis(result,node)
    assert out["rules"][0]["display_rule"] == "30.2.1"
