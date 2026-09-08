from __future__ import annotations
from ipaddress import ip_address, ip_network
from typing import Any
import socket
from .matching import (  # noqa: F401  (re-exported: importers use app.traffic)
    address_match_state,
    address_matches,
    resolve_service_query,
    service_match_state,
    service_matches_query,
    vpn_match_state,
)
from .resolver import ObjectResolver


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
def _uid(v):
    if isinstance(v,str): return v
    if isinstance(v,dict): return v.get("uid","")
    return ""
def _action(rule,res): return res.name(_uid(rule.get("action")))


def _inline_ref_name(rule: dict[str, Any], uid_to_name: dict[str, str] | None = None) -> str | None:
    value = rule.get("inline-layer")
    if not value:
        return None
    if isinstance(value, dict):
        return str(value.get("name") or (uid_to_name or {}).get(str(value.get("uid") or "")) or "") or None
    if isinstance(value, str):
        return (uid_to_name or {}).get(value) or value
    return None



def trace_layer_candidates(
    payload: dict[str, Any],
    src: str,
    dst: str,
    proto: str,
    service: Any,
) -> dict[str, Any]:
    objs={
        o["uid"]:o for o in payload.get("objects-dictionary",[])
        if isinstance(o,dict) and o.get("uid")
    }
    res=ObjectResolver(objs)
    service_query = (
        service if isinstance(service,dict)
        else resolve_service_query(str(service),proto,res)
    )
    candidates=[]
    skipped=[]

    for r in _rules(payload.get("rulebase",[])):
        if not r.get("enabled",True):
            continue

        rn=r.get("rule-number")
        if r.get("source-negate") or r.get("destination-negate") or r.get("service-negate"):
            candidates.append({
                "rule":rn,
                "name":r.get("name","") or "",
                "action":_action(r,res),
                "inline_layer":_inline_ref_name(r),
                "state":"unknown",
                "source_state":"unknown",
                "destination_state":"unknown",
                "service_state":"unknown",
                "vpn_state":"unknown",
                "source_match":"Negated source requires gateway-equivalent evaluation",
                "destination_match":"Negated destination requires gateway-equivalent evaluation",
                "service_match":"Negated service requires gateway-equivalent evaluation",
                "vpn_match":"Not evaluated: the rule is already unevaluable",
            })
            continue

        ss,so=address_match_state(r.get("source"),src,res)
        if ss=="no-match":
            continue

        ds,do=address_match_state(r.get("destination"),dst,res)
        if ds=="no-match":
            continue

        vs,vo=service_match_state(r.get("service"),service_query,res)
        if vs=="no-match":
            continue

        # The VPN column is a fourth dimension. It never returns no-match, so
        # it can only ever weaken a rule from match to unknown - it can never
        # make a provable miss uncertain.
        ns,no=vpn_match_state(r.get("vpn"),res)

        states=(ss,ds,vs,ns)
        overall="match" if all(x=="match" for x in states) else "unknown"
        candidates.append({
            "rule":rn,
            "name":r.get("name","") or "",
            "action":_action(r,res),
            "inline_layer":_inline_ref_name(r),
            "state":overall,
            "source_state":ss,
            "destination_state":ds,
            "service_state":vs,
            "vpn_state":ns,
            "source_match":so,
            "destination_match":do,
            "service_match":vo,
            "vpn_match":no,
            "track":res.name(_uid(r.get("track"))),
            "comments":r.get("comments","") or "",
        })

    return {
        "candidates": candidates,
        "service_query": service_query,
        "skipped": skipped,
    }


def trace_access(payload:dict[str,Any],src:str,dst:str,proto:str,service:Any)->dict[str,Any]:
    """
    Evaluate one Access Control layer only.
    Used by the recursive tree tracer and retained for compatibility.
    """
    objs={o["uid"]:o for o in payload.get("objects-dictionary",[]) if isinstance(o,dict) and o.get("uid")}
    res=ObjectResolver(objs); candidates=[]; skipped=[]
    service_query = (
        service if isinstance(service, dict)
        else resolve_service_query(str(service), proto, res)
    )
    for r in _rules(payload.get("rulebase",[])):
        if not r.get("enabled",True):
            continue
        rn=r.get("rule-number")
        if r.get("source-negate") or r.get("destination-negate") or r.get("service-negate"):
            skipped.append({"rule":rn,"reason":"negation requires gateway-equivalent evaluation"})
            continue

        sm,so=address_matches(r.get("source"),src,res)
        if not sm:
            continue
        dm,do=address_matches(r.get("destination"),dst,res)
        if not dm:
            continue
        vm,vo=service_matches_query(r.get("service"),service_query,res)
        if not vm:
            continue

        action=_action(r,res)
        inline_name=_inline_ref_name(r)
        candidates.append({
            "rule":rn,
            "name":r.get("name","") or "",
            "action":action,
            "inline_layer":inline_name,
            "source_match":so,
            "destination_match":do,
            "service_match":vo,
            "track":res.name(_uid(r.get("track"))),
            "comments":r.get("comments","") or "",
        })
        # Ordered Access Control is first match within the current layer.
        break

    winner=candidates[0] if candidates else None
    return {
        "matched": bool(winner),
        "winner": winner,
        "candidates": candidates,
        "skipped": skipped[:20],
        "result": (winner or {}).get("action", "No matching rule"),
        "service_query": service_query,
    }


def trace_access_tree(
    tree: dict[str, Any],
    src: str,
    dst: str,
    proto: str,
    service: Any,
    selected_root: str | None = None,
) -> dict[str, Any]:
    """
    Inline-aware Access trace with tri-state rule evaluation.

    Unknown parent conditions (for example Security Zone / dynamic-style
    objects) are not treated as No-Match. If their Inline Layer contains an
    exact child match, the result is returned as an inferred configured path.
    """
    nodes=tree.get("layers",[]) or []
    if not nodes:
        return {
            "matched":False,"winner":None,"path":[],"result":"No matching rule",
            "reason":"No Access Control layers were loaded.","confidence":"none",
            "skipped":[]
        }

    by_name={str(n.get("name") or ""):n for n in nodes}
    child_by_parent={}
    for node in nodes:
        pl=str(node.get("parent_layer") or "")
        pr=str(node.get("parent_rule") if node.get("parent_rule") is not None else "")
        if pl and pr:
            child_by_parent[(pl,pr)]=node

    root=by_name.get(selected_root) if selected_root else None
    if root is None:
        root_names=tree.get("root_layers") or ([tree.get("root_layer")] if tree.get("root_layer") else [])
        root=next((by_name.get(n) for n in root_names if by_name.get(n)),None)
    if root is None:
        root=next((n for n in nodes if int(n.get("depth",0) or 0)==0),nodes[0])

    all_objects={}
    for node in nodes:
        for obj in node.get("payload",{}).get("objects-dictionary",[]) or []:
            if isinstance(obj,dict) and obj.get("uid"):
                all_objects[obj["uid"]]=obj
    global_res=ObjectResolver(all_objects)
    service_query=service if isinstance(service,dict) else resolve_service_query(str(service),proto,global_res)

    def recurse(current,path,depth):
        if depth>12:
            return {
                "matched":False,"winner":None,"path":path,
                "result":"Trace depth exceeded","confidence":"none",
                "reason":"Inline Layer nesting exceeded supported trace depth."
            }

        evaluated=trace_layer_candidates(current.get("payload") or {},src,dst,proto,service_query)
        first_uncertain_terminal=None

        for cand in evaluated.get("candidates",[]):
            prefix=str(current.get("display_prefix") or "")
            display_rule=f"{prefix}.{cand.get('rule')}" if prefix else str(cand.get("rule"))
            step={
                **cand,
                "layer":current.get("name"),
                "layer_path":current.get("path"),
                "depth":current.get("depth",0),
                "display_rule":display_rule,
                "parent_rule":current.get("parent_rule"),
            }

            child=child_by_parent.get(
                (str(current.get("name") or ""),str(cand.get("rule")))
            )
            if child is None and cand.get("inline_layer"):
                child=by_name.get(str(cand.get("inline_layer")))

            if child is not None:
                step["transition"]="inline-layer"
                step["inline_layer"]=child.get("name")
                child_result=recurse(child,path+[step],depth+1)

                if child_result.get("matched"):
                    parent_unknown = cand.get("state")=="unknown"
                    child_unknown = child_result.get("confidence")!="exact"
                    child_result["confidence"]="inferred" if (parent_unknown or child_unknown) else "exact"
                    if parent_unknown:
                        child_result["reason"] = (
                            f"Inline child matched, but Parent Rule {display_rule} "
                            "contains condition(s) that require gateway context. "
                            "Result is inferred from configured policy path."
                        )
                    return child_result

                # If an uncertain parent does not yield a child match, continue
                # to later rules rather than declaring it a match.
                if cand.get("state")=="unknown":
                    continue

                # Exact parent matched an inline layer but child did not.
                # Policy path stops here; a later top-level rule is not evaluated.
                return {
                    "matched":False,
                    "winner":None,
                    "path":path+[step],
                    "result":"No final matching rule",
                    "confidence":"exact",
                    "reason":(
                        f"Parent Rule {display_rule} matched exactly and entered "
                        f"Inline Layer {child.get('name')}, but no child rule matched."
                    )
                }

            # Terminal rule.
            if cand.get("state")=="match":
                # An earlier uncertain rule is higher in the ordered rulebase.
                # We cannot safely skip it and claim this later terminal rule
                # (commonly Cleanup) is definitive.
                if first_uncertain_terminal is not None:
                    return {
                        "matched":False,
                        "winner":None,
                        "possible_winner":first_uncertain_terminal,
                        "later_exact_rule":step,
                        "path":path+[first_uncertain_terminal],
                        "result":"UNVERIFIED",
                        "confidence":"unknown",
                        "reason":(
                            f"Earlier Rule {first_uncertain_terminal.get('display_rule')} "
                            "contains condition(s) this static simulator cannot evaluate. "
                            f"Later Rule {display_rule} matches, but cannot be declared final."
                        )
                    }
                step["transition"]="final"
                return {
                    "matched":True,
                    "winner":step,
                    "path":path+[step],
                    "result":step.get("action") or "Matched",
                    "confidence":"exact",
                    "reason":"Terminal Access rule matched exactly."
                }

            # Do not let an uncertain earlier rule silently turn into a fake
            # definitive Cleanup result.
            if first_uncertain_terminal is None:
                first_uncertain_terminal=step

        if first_uncertain_terminal is not None:
            return {
                "matched":False,
                "winner":None,
                "possible_winner":first_uncertain_terminal,
                "path":path+[first_uncertain_terminal],
                "result":"UNVERIFIED",
                "confidence":"unknown",
                "reason":(
                    f"Earlier Rule {first_uncertain_terminal.get('display_rule')} "
                    "contains conditions this static simulator cannot evaluate. "
                    "A later Cleanup rule must not be reported as definitive."
                )
            }

        return {
            "matched":False,"winner":None,"path":path,
            "result":"No matching rule","confidence":"none",
            "reason":f"No matching rule in layer {current.get('name')}."
        }

    return recurse(root,[],0)



# correlate_nat moved to app/nat_correlate.py in v4.20 (see its docstring):
# it became tri-state, and traffic.py is under a 700-line module guard.
# Re-exported so `from app.traffic import correlate_nat` keeps working.
from .nat_correlate import correlate_nat  # noqa: E402,F401

# network_map moved to app/topology_map.py in v4.16 (see its docstring).
# Re-exported so `from app.traffic import network_map` keeps working.
from .topology_map import network_map  # noqa: E402,F401
