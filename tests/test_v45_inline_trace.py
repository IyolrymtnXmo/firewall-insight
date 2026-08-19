from app.traffic import trace_access, trace_access_tree

def obj(uid,name,typ,**kw):
    d={"uid":uid,"name":name,"type":typ}
    d.update(kw)
    return d

def test_trace_recurses_access_sections():
    payload={
        "objects-dictionary":[
            obj("any","Any","CpmiAnyObject"),
            obj("https","https","service-tcp",port="443"),
            obj("accept","Accept","RulebaseAction"),
        ],
        "rulebase":[{
            "type":"access-section","name":"Web","rulebase":[{
                "type":"access-rule","rule-number":60,"enabled":True,
                "source":["any"],"destination":["any"],"service":["https"],"action":"accept"
            }]
        }]
    }
    out=trace_access(payload,"172.16.62.179","142.251.154.4","tcp","https")
    assert out["matched"]
    assert out["winner"]["rule"] == 60

def test_trace_follows_parent_to_inline_terminal_rule():
    common=[
        obj("any","Any","CpmiAnyObject"),
        obj("https","https","service-tcp",port="443"),
        obj("inner","Inner Layer","RulebaseAction"),
        obj("accept","Accept","RulebaseAction"),
    ]
    root={
        "objects-dictionary":common,
        "rulebase":[{
            "type":"access-rule","rule-number":60,"name":"Internet Parent","enabled":True,
            "source":["any"],"destination":["any"],"service":["any"],"action":"inner",
            "inline-layer":{"uid":"il","name":"InternetLayer"}
        }]
    }
    child={
        "objects-dictionary":common,
        "rulebase":[{
            "type":"access-rule","rule-number":35,"name":"Internal surf Internet","enabled":True,
            "source":["any"],"destination":["any"],"service":["https"],"action":"accept"
        }]
    }
    tree={
        "root_layer":"NSTH_POLICY Network",
        "root_layers":["NSTH_POLICY Network"],
        "layers":[
            {"name":"NSTH_POLICY Network","depth":0,"path":"NSTH_POLICY Network","display_prefix":"","payload":root},
            {"name":"InternetLayer","depth":1,"path":"NSTH_POLICY Network → InternetLayer",
             "parent_layer":"NSTH_POLICY Network","parent_rule":60,"display_prefix":"60","payload":child},
        ]
    }
    out=trace_access_tree(tree,"172.16.62.179","142.251.154.4","tcp","https","NSTH_POLICY Network")
    assert out["matched"]
    assert len(out["path"]) == 2
    assert out["path"][0]["display_rule"] == "60"
    assert out["winner"]["display_rule"] == "60.35"
    assert out["winner"]["layer"] == "InternetLayer"
    assert out["winner"]["action"] == "Accept"
