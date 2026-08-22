from conftest import app_source

def test_final_access_summary_uses_four_equal_columns():
    src = app_source()
    assert 'access-summary-grid' in src
    assert 'grid-template-columns:repeat(4,minmax(0,1fr))' in src

def test_the_ui_reports_the_same_version_the_app_declares():
    """Was a pinned literal; the real requirement is that they agree."""
    from app.version import APP_VERSION

    src = app_source()
    assert f'APP_VERSION = "{APP_VERSION}"' in src
    assert "version=APP_VERSION" in src