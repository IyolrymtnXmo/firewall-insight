from conftest import app_source

SRC = app_source()

def test_dashboard_analyze_populates_raw_access_policy():
    block = SRC.split("async function dashboardRefresh()",1)[1].split("function toggleTheme()",1)[0]
    assert "await runAccess();" in block
    assert "await loadPolicyBrowser();" in block
    assert block.index("await runAccess();") < block.index("await loadPolicyBrowser();")

def test_dashboard_status_mentions_access_policy():
    assert "including Access Policy" in SRC
