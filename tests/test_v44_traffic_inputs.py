from app.traffic import trace_access, resolve_service_query
from app.resolver import ObjectResolver

def payload():
    return {
        "objects-dictionary": [
            {"uid":"any","name":"Any","type":"CpmiAnyObject"},
            {"uid":"net","name":"LAN","type":"network","subnet4":"10.0.0.0","mask-length4":8},
            {"uid":"host","name":"Server","type":"host","ipv4-address":"172.16.1.10"},
            {"uid":"https","name":"https","type":"service-tcp","port":"443"},
            {"uid":"custom","name":"APP-8443","type":"service-tcp","port":"8443"},
            {"uid":"acc","name":"Accept","type":"RulebaseAction"},
        ],
        "rulebase": [{
            "type":"access-rule","rule-number":1,"enabled":True,
            "source":["net"],"destination":["host"],"service":["https"],"action":"acc"
        }],
    }

def test_numeric_port_still_works():
    r = trace_access(payload(),"10.1.2.3","172.16.1.10","tcp","443")
    assert r["matched"]

def test_checkpoint_service_name_resolves():
    objs={o["uid"]:o for o in payload()["objects-dictionary"]}
    q=resolve_service_query("APP-8443","tcp",ObjectResolver(objs))
    assert q["port"] == 8443
    assert q["resolved_by"] == "checkpoint-service-object"

def test_standard_service_name_https():
    objs={o["uid"]:o for o in payload()["objects-dictionary"]}
    q=resolve_service_query("https","tcp",ObjectResolver(objs))
    assert q["port"] == 443
