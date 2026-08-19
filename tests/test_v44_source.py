from pathlib import Path
MAIN=Path("app/main.py").read_text(encoding="utf-8")

def test_traffic_ui_accepts_domains_and_service_names():
    assert 'placeholder="Source IP / Domain"' in MAIN
    assert 'placeholder="Destination IP / Domain"' in MAIN
    assert 'placeholder="Port / Service (443, https, ssh)"' in MAIN
    assert "service:port.value.trim()" in MAIN

def test_ui_prefers_hierarchical_display_rule():
    assert "r.display_rule||r.rule" in MAIN
