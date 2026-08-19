from app.analyzer import analyze_rulebase

def test_subnet_shadow_and_action_resolve():
    payload={"objects-dictionary":[
        {"uid":"any","name":"Any","type":"CpmiAnyObject"},
        {"uid":"n8","name":"Big","type":"network","subnet4":"10.0.0.0","mask-length4":8},
        {"uid":"n24","name":"Small","type":"network","subnet4":"10.10.20.0","mask-length4":24},
        {"uid":"https","name":"https","type":"service-tcp","port":"443"},
        {"uid":"accept","name":"Accept","type":"RulebaseAction"}],
        "rulebase":[
        {"type":"access-rule","rule-number":1,"enabled":True,"source":["n8"],"destination":["any"],"service":["https"],"vpn":[],"action":"accept"},
        {"type":"access-rule","rule-number":2,"enabled":True,"source":["n24"],"destination":["any"],"service":["https"],"vpn":[],"action":"accept"}]}
    r=analyze_rulebase(payload)
    assert r["summary"]["potential_shadowed_or_redundant"]==1
    f=r["findings"]["shadowing"][0]
    assert f["classification"]=="Redundant"
    assert f["earlier_action"]=="Accept"
