"""What-if: Kleene negation for negated cells instead of 'unknown' for the whole rule.
Monkeypatches trace_layer_candidates in memory only (the repo is untouched)."""
import random, json, sys
sys.path.insert(0,'.')
import app.traffic as T
from app.resolver import ObjectResolver
from app.matching import address_match_state, service_match_state, vpn_match_state, resolve_service_query
import e2_tristate as E

NEG={"match":"no-match","no-match":"match","unknown":"unknown"}
def patched(payload, src, dst, proto, service):
    objs={o["uid"]:o for o in payload.get("objects-dictionary",[]) if isinstance(o,dict) and o.get("uid")}
    res=ObjectResolver(objs)
    q=service if isinstance(service,dict) else resolve_service_query(str(service),proto,res)
    cands=[]
    for r in T._rules(payload.get("rulebase",[])):
        if not r.get("enabled",True): continue
        ss,_=address_match_state(r.get("source"),src,res)
        if r.get("source-negate"): ss=NEG[ss]
        if ss=="no-match": continue
        ds,_=address_match_state(r.get("destination"),dst,res)
        if r.get("destination-negate"): ds=NEG[ds]
        if ds=="no-match": continue
        vs,_=service_match_state(r.get("service"),q,res)
        if r.get("service-negate"): vs=NEG[vs]
        if vs=="no-match": continue
        ns,_=vpn_match_state(r.get("vpn"),res)
        st="match" if all(x=="match" for x in (ss,ds,vs,ns)) else "unknown"
        cands.append({"rule":r.get("rule-number"),"name":r.get("name",""),"action":T._action(r,res),"inline_layer":T._inline_ref_name(r),"state":st})
    return {"candidates":cands,"service_query":q,"skipped":[]}

def mk(rng,pool,rules):
    src=E.pick(rng,E.rand_addr,pool); dst=E.pick(rng,E.rand_addr,pool); svc=E.pick(rng,E.rand_svc,pool)
    return E.Rule(0,src,dst,svc,"accept" if rng.random()<0.7 else "drop",negate_src=True,tag="negate")
if __name__ == "__main__":
  E.opaque_rule=mk
  T.trace_layer_candidates=patched
  r=E.run(n_policies=20, opaque_frac=0.1, flows=300, seed=11)
  print(r['tristate'], r['twostate'])
  json.dump(r,open('e2_neg_whatif.json','w'),indent=1)
