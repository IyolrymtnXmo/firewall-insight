from conftest import app_source, ui_text

SRC = app_source()

def test_header_has_no_phase_subtitle():
    """Nothing follows the page title inside the header block.

    Asserted as "no paragraph between the </h1> and the </div>" rather than
    as one exact string, so it holds whether the markup is formatted or not.
    Pinning the characters made it a test of the HTML formatter's settings.
    """
    text = ui_text()
    h1 = '<h1>Check Point Firewall Analysis Platform</h1>'
    assert h1 in text
    after = text[text.index(h1) + len(h1):]
    assert after.lstrip().startswith('</div>'), after[:120]
    assert 'Purple Dashboard · Access + NAT + Traffic Path + Topology' not in SRC

def test_alert_count_style_and_logic_present():
    assert '.alert-count{' in SRC
    assert 'function isAlertMetric(label)' in SRC
    assert "'Duplicate NAT'" in SRC
    assert "'Possible No-Translation'" in SRC

def test_dashboard_analyze_keeps_results_for_related_pages():
    assert "await runAccess();" in SRC
    assert "await loadPolicyBrowser();" in SRC
    assert "await runNat();" in SRC
    assert "Results are available in all related pages" in SRC

def test_dashboard_findings_use_alert_badges():
    assert "setDashboardMetric(dShadow,s.potential_shadowed_or_redundant,true)" in SRC
    assert "setDashboardMetric(dDup,s.duplicate_groups,true)" in SRC
    assert "setDashboardMetric(dNatDup,s.duplicate_nat_groups,true)" in SRC
