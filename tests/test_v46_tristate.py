from app.traffic import trace_access_tree

def obj(uid,name,typ,**kw):
    d={"uid":uid,"name":name,"type":typ}
    d.update(kw)
    return d

def base_objects():
    return [
        obj("any","Any","CpmiAnyObject"),
        obj("https","https","service-tcp",port="443"),
        obj("inner","Inner Layer","RulebaseAction"),
        obj("accept","Accept","RulebaseAction"),
        obj("drop","Drop","RulebaseAction"),
        # Static simulator cannot turn this Security Zone into IP atoms.
        obj("zone","InternalZone","security-zone"),
    ]

def test_unknown_zone_parent_can_be_confirmed_by_exact_inline_child():
    common=base_objects()
    root={
        "objects-dictionary":common,
        "rulebase":[
            {
                "type":"access-rule","rule-number":60,"name":"Internet Parent","enabled":True,
                "source":["zone"],"destination":["any"],"service":["any"],"action":"inner",
                "inline-layer":{"uid":"il","name":"InternetLayer"}
            },
            {
                "type":"access-rule","rule-number":132,"name":"Cleanup rule","enabled":True,
                "source":["any"],"destination":["any"],"service":["any"],"action":"drop"
            }
        ]
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
    assert out["winner"]["display_rule"]=="60.35"
    assert out["winner"]["action"]=="Accept"
    assert out["confidence"]=="inferred"

def test_unknown_earlier_terminal_prevents_false_cleanup():
    common=base_objects()
    root={
        "objects-dictionary":common,
        "rulebase":[
            {
                "type":"access-rule","rule-number":60,"name":"Unknown earlier","enabled":True,
                "source":["zone"],"destination":["any"],"service":["https"],"action":"accept"
            },
            {
                "type":"access-rule","rule-number":132,"name":"Cleanup rule","enabled":True,
                "source":["any"],"destination":["any"],"service":["any"],"action":"drop"
            }
        ]
    }
    tree={"root_layer":"Network","root_layers":["Network"],"layers":[
        {"name":"Network","depth":0,"path":"Network","display_prefix":"","payload":root}
    ]}
    out=trace_access_tree(tree,"172.16.62.179","142.251.154.4","tcp","https","Network")
    assert not out["matched"]
    assert out["result"]=="UNVERIFIED"
    assert out["possible_winner"]["display_rule"]=="60"
