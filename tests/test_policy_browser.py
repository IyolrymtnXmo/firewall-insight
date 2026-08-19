from app.policy_browser import browse_access_rulebase

def test_raw_policy_browser_does_not_analyze():
    payload = {
        "layer": "Network",
        "objects-dictionary": [
            {"uid": "any", "name": "Any", "type": "CpmiAnyObject"},
            {"uid": "accept", "name": "Accept", "type": "RulebaseAction"},
        ],
        "rulebase": [
            {
                "type": "access-rule",
                "rule-number": 1,
                "name": "Allow Test",
                "enabled": True,
                "source": ["any"],
                "destination": ["any"],
                "vpn": [],
                "service": ["any"],
                "action": {"uid": "accept", "name": "Accept"},
            }
        ],
    }

    result = browse_access_rulebase(payload)
    assert result["total_rules"] == 1
    assert result["analyzed"] is False
    assert result["rules"][0]["rule"] == 1
    assert result["rules"][0]["action"] == "Accept"

def test_policy_browser_flattens_sections():
    payload = {
        "layer": "Network",
        "objects-dictionary": [],
        "rulebase": [
            {
                "type": "access-section",
                "name": "DMZ",
                "rulebase": [
                    {
                        "type": "access-rule",
                        "rule-number": 10,
                        "name": "Rule 10",
                        "enabled": True,
                        "source": [],
                        "destination": [],
                        "vpn": [],
                        "service": [],
                    }
                ],
            }
        ],
    }
    result = browse_access_rulebase(payload)
    assert result["rules"][0]["section"] == "DMZ"
