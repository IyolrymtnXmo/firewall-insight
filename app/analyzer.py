from __future__ import annotations
from typing import Any
from collections import defaultdict
from .resolver import ObjectResolver, AddrAtom, PortAtom

RULE_FIELDS = ("source","destination","service","vpn","action")

# A cleanup rule is Any/Any/Any by design. Reporting it as an optimization
# finding is a false positive and unfairly lowers the optimization score.
CLEANUP_ACTIONS = {"drop", "reject"}

def _rules(items):
    out=[]
    for x in items or []:
        if not isinstance(x,dict):
            continue
        if x.get("type")=="access-rule":
            out.append(x)
        nested=x.get("rulebase")
        if isinstance(nested,list):
            out.extend(_rules(nested))
    return out
def _action_uid(rule):
    a=rule.get("action")
    return a if isinstance(a,str) else a.get("uid","") if isinstance(a,dict) else ""
def _action_name(rule,res):
    a=rule.get("action")
    if isinstance(a,dict): return str(a.get("name") or a.get("uid") or "")
    return res.name(a)
def is_cleanup_rule(rule, rules, res) -> bool:
    """
    True when `rule` is the layer's implicit-deny / cleanup rule.

    Identified positionally (last ordered rule in this layer) plus a deny
    action, NOT by name - rule names vary per administrator and language.
    """
    if not rules or rule is not rules[-1]:
        return False
    return _action_name(rule, res).strip().lower() in CLEANUP_ACTIONS


def _sig(rule,res):
    return (tuple(sorted(res.uids(rule.get("source")))),tuple(sorted(res.uids(rule.get("destination")))),tuple(sorted(res.uids(rule.get("service")))),tuple(sorted(res.uids(rule.get("vpn")))),_action_uid(rule),bool(rule.get("enabled",True)),bool(rule.get("source-negate",False)),bool(rule.get("destination-negate",False)),bool(rule.get("service-negate",False)))

def _intervals_cover(earlier, later) -> bool:
    if earlier is None or later is None: return False
    for l in later:
        ok=False
        for e in earlier:
            if isinstance(l,AddrAtom):
                if isinstance(e,AddrAtom) and e.version==l.version and e.start<=l.start and e.end>=l.end: ok=True; break
            else:
                if isinstance(e,PortAtom) and (e.proto=="any" or e.proto==l.proto) and e.start<=l.start and e.end>=l.end: ok=True; break
        if not ok: return False
    return True

def _dimension_cover(earlier_values,later_values,res: ObjectResolver,kind:str):
    eu=res.uids(earlier_values); lu=res.uids(later_values)
    if res.is_any(earlier_values): return True,"Any"
    if set(lu).issubset(set(eu)): return True,"Exact object/group UID coverage"
    ea=[]; la=[]
    for uid in eu:
        part=res.address_atoms(uid) if kind=="address" else res.service_atoms(uid)
        if part is None: return False,"Unsupported object type"
        ea.extend(part)
    for uid in lu:
        part=res.address_atoms(uid) if kind=="address" else res.service_atoms(uid)
        if part is None: return False,"Unsupported object type"
        la.extend(part)
    if _intervals_cover(ea,la): return True,"Subnet/range coverage" if kind=="address" else "Protocol/port coverage"
    return False,"Not contained"

def analyze_rulebase(payload: dict[str,Any]) -> dict[str,Any]:
    rules=_rules(payload.get("rulebase",[]))
    objs={o["uid"]:o for o in payload.get("objects-dictionary",[]) if isinstance(o,dict) and o.get("uid")}
    res=ObjectResolver(objs)
    disabled=[]; any_src=[]; any_dst=[]; any_svc=[]; broad=[]; zero_hit=[]; cleanup=[]
    sigs=defaultdict(list)
    rows=[]
    for r in rules:
        sigs[_sig(r,res)].append(r)
        n=r.get("rule-number")
        if not r.get("enabled",True): disabled.append(n)
        sa,da,sv=res.is_any(r.get("source")),res.is_any(r.get("destination")),res.is_any(r.get("service"))
        if sa:any_src.append(n)
        if da:any_dst.append(n)
        if sv:any_svc.append(n)
        if sa and da and sv:
            if is_cleanup_rule(r,rules,res): cleanup.append(n)
            else: broad.append(n)
        hits=r.get("hits") if isinstance(r.get("hits"),dict) else {}
        hv=hits.get("value")
        if hv == 0: zero_hit.append(n)
        rows.append({"rule":n,"name":r.get("name","") or "","enabled":r.get("enabled",True),"source":res.describe_list(r.get("source")),"destination":res.describe_list(r.get("destination")),"service":res.describe_list(r.get("service")),"action":_action_name(r,res),"hits":hv,"last_hit":hits.get("last-date") or hits.get("last-hit")})
    duplicates=[]
    for group in sigs.values():
        if len(group)>1:
            members=[]
            for r in group:
                members.append({"rule":r.get("rule-number"),"name":r.get("name","") or "","source":res.describe_list(r.get("source")),"destination":res.describe_list(r.get("destination")),"service":res.describe_list(r.get("service")),"vpn":res.describe_list(r.get("vpn")),"action":_action_name(r,res),"enabled":r.get("enabled",True)})
            duplicates.append({"group":len(duplicates)+1,"rule_numbers":[m["rule"] for m in members],"names":[m["name"] for m in members],"members":members,"classification":"Exact Duplicate","recommendation":f"Review later duplicate rule(s) {', '.join(str(m['rule']) for m in members[1:])} against earliest rule {members[0]['rule']} before any change."})
    shadows=[]; enabled=[r for r in rules if r.get("enabled",True)]
    for idx,later in enumerate(enabled):
        if any(later.get(k,False) for k in ("source-negate","destination-negate","service-negate")): continue
        if later.get("inline-layer"): continue
        for earlier in enabled[:idx]:
            if any(earlier.get(k,False) for k in ("source-negate","destination-negate","service-negate")): continue
            if earlier.get("inline-layer"): continue
            # VPN must be exact/Any-equivalent for conservative result.
            ev,lv=set(res.uids(earlier.get("vpn"))),set(res.uids(later.get("vpn")))
            if ev != lv: continue
            sc,sreason=_dimension_cover(earlier.get("source"),later.get("source"),res,"address")
            if not sc: continue
            dc,dreason=_dimension_cover(earlier.get("destination"),later.get("destination"),res,"address")
            if not dc: continue
            vc,vreason=_dimension_cover(earlier.get("service"),later.get("service"),res,"service")
            if not vc: continue
            ea,la=_action_name(earlier,res),_action_name(later,res)
            same=ea==la
            shadows.append({"rule":later.get("rule-number"),"rule_name":later.get("name","") or "","covered_by":earlier.get("rule-number"),"covered_by_name":earlier.get("name","") or "","classification":"Redundant" if same else "Shadowed / action conflict","risk":"Medium" if same else "High","earlier_action":ea,"later_action":la,"source_reason":sreason,"destination_reason":dreason,"service_reason":vreason,"earlier":{"source":res.describe_list(earlier.get("source")),"destination":res.describe_list(earlier.get("destination")),"service":res.describe_list(earlier.get("service"))},"later":{"source":res.describe_list(later.get("source")),"destination":res.describe_list(later.get("destination")),"service":res.describe_list(later.get("service"))}})
            break
    score=max(0,100-min(len(broad)*8,24)-min(len(duplicates)*3,15)-min(len(shadows)*2,25)-min(len(disabled),10))
    return {"summary":{"total_rules":len(rules),"disabled_rules":len(disabled),"zero_hit_rules":len(zero_hit),"rules_with_any_source":len(any_src),"rules_with_any_destination":len(any_dst),"rules_with_any_service":len(any_svc),"any_any_any_rules":len(broad),"cleanup_rules":len(cleanup),"duplicate_groups":len(duplicates),"potential_shadowed_or_redundant":len(shadows),"optimization_score":score},"findings":{"disabled_rule_numbers":disabled,"zero_hit_rule_numbers":zero_hit,"any_any_any_rule_numbers":broad,"cleanup_rule_numbers":cleanup,"duplicates":duplicates,"shadowing":shadows},"rules":rows,"notes":["Read-only: no add/set/delete/publish/install-policy operations are implemented.","Shadow analysis skips negated rules and inline-layer rules to reduce false positives.","A trailing Any/Any/Any Drop/Reject rule is recognised as the layer cleanup rule and is reported separately, not as an Any/Any/Any finding.","Unknown/dynamic/identity-aware object types are treated conservatively and are not assumed to be contained."]}

def collect_referenced_uids(payload: dict[str,Any]) -> set[str]:
    out=set()
    for r in _rules(payload.get("rulebase",[])):
        for key in RULE_FIELDS:
            v=r.get(key)
            if isinstance(v,str): out.add(v)
            elif isinstance(v,list):
                for x in v:
                    if isinstance(x,str): out.add(x)
                    elif isinstance(x,dict) and x.get("uid"): out.add(x["uid"])
            elif isinstance(v,dict) and v.get("uid"): out.add(v["uid"])
    return out
