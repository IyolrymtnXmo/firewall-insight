from conftest import app_source, ui_text

def test_sidebar_separates_raw_and_analyze_adjacent():
    """Raw Access Policy must sit before Analyze in the sidebar.

    Asserted by attribute position rather than one exact attribute string, so
    adding an unrelated attribute (data-label for the collapsed rail tooltip)
    cannot fail a test about menu ordering.

    v4.30 replaced the ◈ ▤ ◇ ⇄ ➜ glyph set with drawn SVG icons, so the
    label assertion is now about the words on the item and the fact that the
    item carries an icon - not about which character sat in front of it.
    """
    src = app_source()
    raw = 'data-page="browser"'
    ana = 'data-page="access"'
    assert raw in src
    assert ana in src
    assert src.index(raw) < src.index(ana)
    # the label text, whatever the formatter did to the line breaks
    assert "Access Policy</span></button>" in ui_text()
    assert "Analyze</span></button>" in ui_text()
    assert 'data-label="Access Policy"' in src
    assert 'data-label="Analyze"' in src

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
