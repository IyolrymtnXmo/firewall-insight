from app.nat_analyzer import analyze_nat_rulebase

def test_empty_nat():
    d = analyze_nat_rulebase({"rulebase": [], "objects-dictionary": []})
    assert d["summary"]["total_nat_rules"] == 0
    assert d["summary"]["duplicate_nat_groups"] == 0
