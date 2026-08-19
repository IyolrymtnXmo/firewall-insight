from pathlib import Path

SRC = Path("app/main.py").read_text(encoding="utf-8")

def test_header_has_no_phase_subtitle():
    assert '<h1>Check Point Firewall Analysis Platform</h1></div>' in SRC
    assert 'Purple Dashboard · Access + NAT + Traffic Path + Topology</p>' not in SRC

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
