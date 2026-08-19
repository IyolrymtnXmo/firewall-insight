from app.analyzer import analyze_rulebase

def test_analyzer_counts_rules_inside_sections():
    payload = {
        "objects-dictionary": [],
        "rulebase": [
            {
                "type": "access-section",
                "name": "Section A",
                "rulebase": [
                    {"type": "access-rule", "rule-number": 1, "enabled": True},
                    {"type": "access-rule", "rule-number": 2, "enabled": True},
                ],
            }
        ],
    }
    result = analyze_rulebase(payload)
    assert result["summary"]["total_rules"] == 2
