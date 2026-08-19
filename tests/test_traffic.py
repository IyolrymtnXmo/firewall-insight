from app.traffic import trace_access, network_map

def test_trace_simple():
    anyu='any'; net='net'; host='host'; svc='svc'; acc='acc'
    payload={'objects-dictionary':[
        {'uid':anyu,'name':'Any','type':'CpmiAnyObject'},
        {'uid':net,'name':'LAN','type':'network','subnet4':'10.0.0.0','mask-length4':8},
        {'uid':host,'name':'Server','type':'host','ipv4-address':'172.16.1.10'},
        {'uid':svc,'name':'https','type':'service-tcp','port':'443'},
        {'uid':acc,'name':'Accept','type':'RulebaseAction'}],
        'rulebase':[{'type':'access-rule','rule-number':1,'enabled':True,'source':[net],'destination':[host],'service':[svc],'action':acc}]}
    r=trace_access(payload,'10.1.2.3','172.16.1.10','tcp',443)
    assert r['matched'] and r['winner']['rule']==1 and r['winner']['action']=='Accept'

def test_map_interfaces():
    d=network_map([{'uid':'g1','name':'GW1','type':'simple-gateway','interfaces':[{'name':'eth0','ipv4-address':'10.0.0.1','ipv4-mask-length':24}]}])
    assert d['count']==3 and len(d['edges'])==2
