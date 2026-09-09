from conftest import app_source

MAIN = app_source()

def test_raw_access_policy_groups_inline_under_parent():
    assert "function accessHierarchyRows(rows)" in MAIN
    assert "hierarchyKey(r.parent_layer,r.parent_rule)" in MAIN
    assert "inline-child-row" in MAIN
    # An inline row must name the rule it hangs under, or a reader scrolling
    # past the parent cannot tell which layer they are inside. v4.30 shortened
    # the wording from "under Parent Rule 8" to "under rule 8" when the number
    # moved into the rule gutter; the requirement is the reference, not the
    # phrasing.
    assert "under rule ${esc(r.parent_rule)}" in MAIN

def test_dashboard_has_inline_findings_summary():
    assert 'id="inlineAnalysisSummary"' in MAIN
    assert "renderInlineDashboardSummary(s)" in MAIN
    assert "inline_shadow_findings" in MAIN
    assert "inline_duplicate_groups" in MAIN
    assert "inline_any_any_any_rules" in MAIN
