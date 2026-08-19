from conftest import app_source

def test_final_access_summary_uses_four_equal_columns():
    src = app_source()
    assert 'access-summary-grid' in src
    assert 'grid-template-columns:repeat(4,minmax(0,1fr))' in src

def test_final_version_label():
    src = app_source()
    assert 'APP_VERSION = "4.13.0"' in src
    assert "version=APP_VERSION" in src
