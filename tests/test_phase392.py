from conftest import app_source

def test_dashboard_is_package_first_and_traffic_keeps_layer_selector():
    src = app_source()
    assert "layerControl.style.display=(id==='traffic')" in src
    assert "id==='dashboard'||id==='browser'||id==='access'||id==='nat'||id==='traffic'" in src
    assert 'id="layerControl"' in src
    assert 'id="packageControl"' in src
