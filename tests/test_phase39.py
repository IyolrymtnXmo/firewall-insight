from conftest import app_source

def test_access_policy_restored_to_original_browser_and_analyze_sidebar_removed():
    src = app_source()
    assert 'data-page="browser"' in src
    assert '>▤ Access Policy<' in src
    assert '<section id="browser" class="page">' in src
    

def test_nat_has_disabled_and_no_translation_drilldowns():
    src = app_source()
    assert "Disabled NAT" in src
    assert "Possible No-Translation" in src
    assert 'nat-disabled-view' in src
    assert 'nat-notrans-view' in src
