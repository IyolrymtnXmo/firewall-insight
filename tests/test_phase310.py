from pathlib import Path

def test_sidebar_separates_raw_and_analyze_adjacent():
    src = Path("app/main.py").read_text(encoding="utf-8")
    raw = 'data-page="browser" onclick="showPage(\'browser\',this)">▤ Access Policy</button>'
    ana = 'data-page="access" onclick="showPage(\'access\',this)">◇ Analyze</button>'
    assert raw in src
    assert ana in src
    assert src.index(raw) < src.index(ana)

def test_raw_access_page_and_analyze_page_both_exist():
    src = Path("app/main.py").read_text(encoding="utf-8")
    assert '<section id="browser" class="page">' in src
    assert '<section id="access" class="page">' in src
    assert '<h2>Access Policy</h2>' in src
    assert '<h2>Analyze</h2>' in src

def test_dashboard_quick_actions_are_distinct():
    src = Path("app/main.py").read_text(encoding="utf-8")
    assert "Open Access Policy" in src
    assert "Open Analyze" in src
