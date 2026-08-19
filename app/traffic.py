from __future__ import annotations
from ipaddress import ip_address, ip_network
from typing import Any
import socket
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


def _domain_candidates(text: str) -> tuple[list[str], str | None]:
    value = str(text or "").strip()
    try:
        ip_address(value)
        return [value], None
    except ValueError:
        pass

    ips = []
    try:
        for info in socket.getaddrinfo(value, None, type=socket.SOCK_STREAM):
            addr = info[4][0]
            if addr not in ips:
                ips.append(addr)
    except OSError as exc:
        return [], str(exc)
    return ips, None


def _domain_object_match(uid: str, domain: str, res: ObjectResolver) -> bool:
    o = res.obj(uid)
    name = str(o.get("name") or "").strip().lower()
    typ = str(o.get("type") or "").lower()
    query = str(domain or "").strip().lower().rstrip(".")

    if not query:
        return False

    # Check Point DNS-domain objects commonly use the domain itself as name.
    candidate = name.lstrip(".").rstrip(".")
    if "dns-domain" in typ or "domain" in typ:
        if candidate == query:
            return True
        # Leading-dot / sub-domain style object: .example.com
        if name.startswith(".") and (query == candidate or query.endswith("." + candidate)):
            return True

    members = o.get("members")
    if isinstance(members, list):
        for child in members:
            cu = child if isinstance(child, str) else child.get("uid") if isinstance(child, dict) else None
            if cu and _domain_object_match(cu, query, res):
                return True
    return False


def address_matches(values: Any, address_text: str, res: ObjectResolver) -> tuple[bool, str]:
    raw = str(address_text or "").strip()
    try:
        ip = ip_address(raw)
        ips = [ip]
        is_domain = False
        dns_error = None
    except ValueError:
        is_domain = True
        resolved, dns_error = _domain_candidates(raw)
        ips = []
        for value in resolved:
            try:
                ips.append(ip_address(value))
            except ValueError:
                pass

    for uid in res.uids(values):
        if res.is_any_uid(uid):
            if is_domain and ips:
                return True, f"Any · {raw} → {', '.join(str(x) for x in ips[:4])}"
            return True, "Any"

        if is_domain and _domain_object_match(uid, raw, res):
            return True, f"{res.describe_uid(uid)} · domain match"

        atoms = res.address_atoms(uid)
        if atoms is None:
            continue
        for ip in ips:
            n = int(ip)
            if any(a.version == ip.version and a.start <= n <= a.end for a in atoms):
                if is_domain:
                    return True, f"{res.describe_uid(uid)} · {raw} → {ip}"
                return True, res.describe_uid(uid)

    if is_domain:
        if ips:
            return False, f"No matching object for {raw} ({', '.join(str(x) for x in ips[:4])})"
        return False, f"Domain not resolved/matched: {raw}" + (f" ({dns_error})" if dns_error else "")
    return False, "No matching object"


def _service_object_by_name(name: str, res: ObjectResolver) -> tuple[str, list] | None:
    q = str(name or "").strip().lower()
    if not q:
        return None
    for uid, obj in res.objects.items():
        if str(obj.get("name") or "").strip().lower() != q:
            continue
        atoms = res.service_atoms(uid)
        if atoms:
            return uid, atoms
    return None


def resolve_service_query(service_text: str, proto: str, res: ObjectResolver) -> dict[str, Any]:
    raw = str(service_text or "").strip()
    p = str(proto or "tcp").lower()

    if raw.isdigit():
        port = int(raw)
        if not (0 <= port <= 65535):
            raise ValueError("Port must be between 0 and 65535")
        return {
            "input": raw, "protocol": p, "port": port,
            "atoms": [(p, port, port)],
            "resolved_by": "numeric-port",
            "display": f"{p.upper()}/{port}",
        }

    cp_obj = _service_object_by_name(raw, res)
    if cp_obj:
        uid, atoms = cp_obj
        atom_tuples = [(a.proto, a.start, a.end) for a in atoms]
        # Use a representative port for legacy NAT/display paths.
        selected = next((a for a in atoms if a.proto in (p, "any")), atoms[0])
        return {
            "input": raw,
            "protocol": selected.proto if selected.proto != "any" else p,
            "port": selected.start,
            "atoms": atom_tuples,
            "resolved_by": "checkpoint-service-object",
            "object_uid": uid,
            "display": res.describe_uid(uid),
        }

    # OS standard service database: https, ssh, smtp, domain, ntp, etc.
    try:
        port = socket.getservbyname(raw.lower(), p)
        return {
            "input": raw, "protocol": p, "port": port,
            "atoms": [(p, port, port)],
            "resolved_by": "standard-service-name",
            "display": f"{raw} ({p.upper()}/{port})",
        }
    except OSError:
        raise ValueError(
            f"Unknown service '{raw}'. Enter a port number, a standard service "
            f"name (for example https/ssh/smtp), or an exact Check Point service object name."
        )


def service_matches_query(values: Any, query: dict[str, Any], res: ObjectResolver) -> tuple[bool, str]:
    q_atoms = query.get("atoms") or []
    for uid in res.uids(values):
        if res.is_any_uid(uid):
            return True, "Any"
        atoms = res.service_atoms(uid)
        if atoms is None:
            continue
        for qp, qs, qe in q_atoms:
            for a in atoms:
                proto_ok = a.proto == "any" or qp == "any" or a.proto == qp
                # A queried service is covered when its range overlaps the rule service.
                if proto_ok and not (qe < a.start or qs > a.end):
                    return True, res.describe_uid(uid)
    return False, "No matching service"


def _inline_ref_name(rule: dict[str, Any], uid_to_name: dict[str, str] | None = None) -> str | None:
    value = rule.get("inline-layer")
    if not value:
        return None
    if isinstance(value, dict):
        return str(value.get("name") or (uid_to_name or {}).get(str(value.get("uid") or "")) or "") or None
    if isinstance(value, str):
        return (uid_to_name or {}).get(value) or value
    return None



def address_match_state(values: Any, address_text: str, res: ObjectResolver) -> tuple[str, str]:
    """
    Tri-state address matcher:
      match    = condition is proven to match
      no-match = condition is proven not to match
      unknown  = rule uses an object type this static simulator cannot evaluate
    """
    raw = str(address_text or "").strip()
    try:
        ip = ip_address(raw)
        ips = [ip]
        is_domain = False
    except ValueError:
        is_domain = True
        resolved, _ = _domain_candidates(raw)
        ips = []
        for value in resolved:
            try:
                ips.append(ip_address(value))
            except ValueError:
                pass

    saw_unknown = False
    unknown_names = []

    for uid in res.uids(values):
        if res.is_any_uid(uid):
            return "match", "Any"

        obj = res.obj(uid)
        typ = str(obj.get("type") or "").lower()
        name = str(obj.get("name") or uid)

        if is_domain and _domain_object_match(uid, raw, res):
            return "match", f"{res.describe_uid(uid)} · domain match"

        atoms = res.address_atoms(uid)
        if atoms is None:
            saw_unknown = True
            unknown_names.append(f"{name} [{typ or 'unknown'}]")
            continue

        for ip in ips:
            n = int(ip)
            if any(a.version == ip.version and a.start <= n <= a.end for a in atoms):
                return "match", res.describe_uid(uid)

    if saw_unknown:
        return "unknown", "Static match unavailable for " + ", ".join(unknown_names[:4])

    return "no-match", "No matching object"


def service_match_state(values: Any, query: dict[str, Any], res: ObjectResolver) -> tuple[str, str]:
    q_atoms = query.get("atoms") or []
    saw_unknown = False
    unknown_names = []

    for uid in res.uids(values):
        if res.is_any_uid(uid):
            return "match", "Any"

        atoms = res.service_atoms(uid)
        if atoms is None:
            obj = res.obj(uid)
            saw_unknown = True
            unknown_names.append(
                f"{obj.get('name') or uid} [{obj.get('type') or 'unknown'}]"
            )
            continue

        for qp, qs, qe in q_atoms:
            for a in atoms:
                proto_ok = a.proto == "any" or qp == "any" or a.proto == qp
                if proto_ok and not (qe < a.start or qs > a.end):
                    return "match", res.describe_uid(uid)

    if saw_unknown:
        return "unknown", "Static service match unavailable for " + ", ".join(unknown_names[:4])
    return "no-match", "No matching service"


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
                "source_match":"Negated source requires gateway-equivalent evaluation",
                "destination_match":"Negated destination requires gateway-equivalent evaluation",
                "service_match":"Negated service requires gateway-equivalent evaluation",
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

        states=(ss,ds,vs)
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
            "source_match":so,
            "destination_match":do,
            "service_match":vo,
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



def _nat_rules(items):
    out=[]
    def walk(xs):
        for x in xs or []:
            if not isinstance(x,dict): continue
            if x.get("type")=="nat-rule": out.append(x)
            if isinstance(x.get("rulebase"),list): walk(x["rulebase"])
    walk(items); return out

def correlate_nat(payload:dict[str,Any],src:str,dst:str,res_extra:dict[str,dict]|None=None)->list[dict[str,Any]]:
    objs={o["uid"]:o for o in payload.get("objects-dictionary",[]) if isinstance(o,dict) and o.get("uid")}
    if res_extra: objs.update(res_extra)
    res=ObjectResolver(objs); findings=[]
    for r in _nat_rules(payload.get("rulebase",[])):
        if not r.get("enabled",True): continue
        sm,so=address_matches(r.get("original-source"),src,res)
        dm,do=address_matches(r.get("original-destination"),dst,res)
        if not (sm and dm): continue
        findings.append({"rule":r.get("rule-number"),"name":r.get("name","") or "","original_source":so,"original_destination":do,"translated_source":res.describe_list(r.get("translated-source")),"translated_destination":res.describe_list(r.get("translated-destination")),"translated_service":res.describe_list(r.get("translated-service"))})
        break
    return findings

def network_map(objects:list[dict[str,Any]])->dict[str,Any]:
    nodes=[]; edges=[]; subnet_nodes={}
    for o in objects:
        uid=o.get("uid"); name=o.get("name") or uid; typ=o.get("type","")
        if not uid: continue
        ips=[]
        for k in ("ipv4-address","ip-address"):
            if o.get(k): ips.append(str(o[k]))
        role="gateway" if typ in ("simple-gateway","cluster-member","CpmiGatewayCluster") or "gateway" in typ.lower() else "management" if typ in ("checkpoint-host",) or "management" in name.lower() or "mgmt" in name.lower() else "device"
        nodes.append({"id":uid,"name":name,"type":typ,"role":role,"ips":ips})
        ifaces=o.get("interfaces") if isinstance(o.get("interfaces"),list) else []
        for i,iface in enumerate(ifaces):
            if not isinstance(iface,dict): continue
            ip=iface.get("ipv4-address") or iface.get("ip-address")
            mask=iface.get("ipv4-mask-length") or iface.get("mask-length4") or iface.get("mask-length")
            if not ip or str(ip)=="0.0.0.0": continue
            iname=iface.get("name") or f"interface {i+1}"
            nid=f"{uid}:if:{i}"
            cidr=f"{ip}/{mask}" if mask is not None else str(ip)
            nodes.append({"id":nid,"name":iname,"type":"interface","role":"interface","ips":[str(ip)],"cidr":cidr,"parent":uid})
            edges.append({"from":uid,"to":nid,"label":"interface"})
            if mask is not None:
                try:
                    net=str(ip_network(cidr,strict=False))
                    sid=f"net:{net}"
                    if sid not in subnet_nodes:
                        subnet_nodes[sid]={"id":sid,"name":net,"type":"network","role":"network","ips":[net]}
                    edges.append({"from":nid,"to":sid,"label":"connected subnet"})
                except ValueError:
                    pass
    nodes.extend(subnet_nodes.values())
    return {"nodes":nodes,"edges":edges,"count":len(nodes),"topology":True,"limitations":["Connected subnets are calculated from configured interface IPv4 address and mask.","Links show configured logical relationships only; physical cabling, switches and live routing are not inferred."]}
