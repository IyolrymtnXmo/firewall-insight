from pathlib import Path

def test_final_access_summary_uses_four_equal_columns():
    src = Path("app/main.py").read_text(encoding="utf-8")
    assert 'access-summary-grid' in src
    assert 'grid-template-columns:repeat(4,minmax(0,1fr))' in src

def test_final_version_label():
    src = Path("app/main.py").read_text(encoding="utf-8")
    assert 'APP_VERSION = "4.10.0"' in src
    assert "version=APP_VERSION" in src
