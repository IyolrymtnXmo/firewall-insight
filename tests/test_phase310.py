from conftest import app_source

def test_sidebar_separates_raw_and_analyze_adjacent():
    """Raw Access Policy must sit before Analyze in the sidebar.

    Asserted by attribute position rather than one exact attribute string, so
    adding an unrelated attribute (data-label for the collapsed rail tooltip)
    cannot fail a test about menu ordering.
    """
    src = app_source()
    raw = 'data-page="browser"'
    ana = 'data-page="access"'
    assert raw in src
    assert ana in src
    assert src.index(raw) < src.index(ana)
    assert "▤ Access Policy</button>" in src
    assert "◇ Analyze</button>" in src

def test_raw_access_page_and_analyze_page_both_exist():
    src = app_source()
    assert '<section id="browser" class="page">' in src
    assert '<section id="access" class="page">' in src
    assert '<h2>Access Policy</h2>' in src
    assert '<h2>Analyze</h2>' in src

def test_dashboard_quick_actions_are_distinct():
    src = app_source()
    assert "Open Access Policy" in src
    assert "Open Analyze" in src
