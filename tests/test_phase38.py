from conftest import app_source
from app.nat_analyzer import analyze_nat_rulebase


def test_nat_scalar_fields_are_rendered():
    payload = {
        "objects-dictionary": [
            {"uid": "src1", "name": "Source-Host", "type": "host", "ipv4-address": "10.0.0.10"},
            {"uid": "dst1", "name": "Destination-Host", "type": "host", "ipv4-address": "192.0.2.10"},
            {"uid": "https", "name": "https", "type": "service-tcp", "port": "443"},
            {"uid": "any", "name": "Any", "type": "CpmiAnyObject"},
        ],
        "rulebase": [
            {
                "type": "nat-rule",
                "rule-number": 1,
                "original-source": "src1",
                "original-destination": "dst1",
                "original-service": "https",
                "translated-source": "Original",
                "translated-destination": "dst1",
                "translated-service": "Original",
                "install-on": ["any"],
                "method": "static",
            }
        ],
    }
    result = analyze_nat_rulebase(payload)
    row = result["rules"][0]
    assert "Source-Host" in row["original_source"]
    assert "Destination-Host" in row["original_destination"]
    assert "https" in row["original_service"]
    assert row["translated_source"] == "Original"


def test_nat_scalar_fields_do_not_false_duplicate():
    payload = {
        "objects-dictionary": [],
        "rulebase": [
            {"type": "nat-rule", "rule-number": 1, "original-source": "a", "translated-source": "x"},
            {"type": "nat-rule", "rule-number": 2, "original-source": "b", "translated-source": "y"},
        ],
    }
    result = analyze_nat_rulebase(payload)
    assert result["summary"]["duplicate_nat_groups"] == 0


def test_sidebar_access_policy_entry_exists():
    source = app_source()
    assert "▤ Access Policy" in source
    assert 'data-page="browser"' in source
