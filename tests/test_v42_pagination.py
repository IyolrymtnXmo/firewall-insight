from pathlib import Path
from app.checkpoint import _merge_rulebase_page

CP = Path("app/checkpoint.py").read_text(encoding="utf-8")

def test_section_wrappers_merge_without_duplicate_rules():
    target = [{
        "type": "access-section",
        "uid": "s1",
        "name": "Section",
        "rulebase": [{"type": "access-rule", "uid": "r1", "rule-number": 1}],
    }]
    incoming = [{
        "type": "access-section",
        "uid": "s1",
        "name": "Section",
        "rulebase": [
            {"type": "access-rule", "uid": "r1", "rule-number": 1},
            {"type": "access-rule", "uid": "r2", "rule-number": 2},
        ],
    }]
    _merge_rulebase_page(target, incoming)
    assert len(target) == 1
    assert len(target[0]["rulebase"]) == 2

def test_access_and_nat_pagination_use_response_to():
    assert CP.count('response_to = page.get("to")') >= 2
    assert CP.count('next_offset = int(response_to)') >= 2
