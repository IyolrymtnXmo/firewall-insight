from pathlib import Path

def test_dashboard_is_package_first_and_traffic_keeps_layer_selector():
    src = Path("app/main.py").read_text(encoding="utf-8")
    assert "layerControl.style.display=(id==='traffic')" in src
    assert "id==='dashboard'||id==='browser'||id==='access'||id==='nat'||id==='traffic'" in src
    assert 'id="layerControl"' in src
    assert 'id="packageControl"' in src
