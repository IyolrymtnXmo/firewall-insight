"""E2b - soundness of the tri-state simulator on policies WITH Inline Layers.

Ground truth is an R82-style gateway model written here, independently of app/:
  * one Ordered Layer ("L"); first match, top to bottom
  * a rule whose action is an Inline Layer sends the connection into the child
    layer; the child decides (first match); if no child rule matches, the
    child layer's *implicit cleanup action* (Drop or Accept, configurable)
    decides and the connection never returns to the parent layer
  * if no rule of the ordered layer matches, its implicit cleanup (Drop) decides
  * opaque objects (Security Zone, Dynamic Object, DCE-RPC, negation) are
    evaluated on their hidden runtime value

A tool answer is DEFINITE when it is
  matched + confidence "exact"                     -> claims (rule, action)
  "No matching rule" + confidence "none"           -> claims root implicit cleanup
  "No final matching rule" + confidence "exact"    -> claims child implicit cleanup
Everything else (inferred / unknown / UNVERIFIED) is an abstention.
"""
from __future__ import annotations
import ipaddress, random, sys, json, importlib
from collections import Counter
sys.path.insert(0, ".")
from gen import Pool, Rule, Obj, payload, dim_iv, contains
from e1_anomaly import rand_addr, rand_svc, pick
from e2_tristate import truth_match, query

TRAFFIC_MODULE = sys.argv[1] if len(sys.argv) > 1 else "app.traffic"


class IRule(Rule):
    pass


def make_rule(rng, pool, opaque_frac, src=None):
    """a rule; with probability opaque_frac it contains one unevaluable element"""
    s = src or pick(rng, rand_addr, pool)
    d = pick(rng, rand_addr, pool)
    v = pick(rng, rand_svc, pool)
    neg, tag = False, ""
    if rng.random() < opaque_frac:
        tag = rng.choice(["zone", "dynobj", "dcerpc", "negate"])
        hidden = lambda: [f"10.{rng.randrange(256)}.{rng.randrange(256)}.0/24" for _ in range(rng.randint(1, 3))]
        if tag == "zone":
            s = [pool.opaque_addr("security-zone", hidden())]
        elif tag == "dynobj":
            d = [pool.opaque_addr("dynamic-object", hidden())]
        elif tag == "dcerpc":
            v = [pool.dcerpc()]
        else:
            neg = True
    r = Rule(0, s, d, v, "accept" if rng.random() < 0.7 else "drop", negate_src=neg, tag=tag)
    r.inline = None
    return r


def build(rng, n_rules=30, n_inline=4, child_rules=6, opaque_frac=0.2):
    pool = Pool(rng)
    pool.objs["inline"] = Obj("inline", {"uid": "inline", "name": "Inline Layer", "type": "RulebaseAction"}, None)
    root = [make_rule(rng, pool, opaque_frac) for _ in range(n_rules)]
    children = {}
    for idx in rng.sample(range(n_rules), n_inline):
        a = rng.randrange(256)
        region = f"10.{a}.0.0/16"
        parent = root[idx]
        # the parent scopes a /16; sometimes through an opaque Security Zone
        if rng.random() < opaque_frac * 1.5:
            parent.src = [pool.opaque_addr("security-zone", [region])]; parent.tag = "zone"
        else:
            parent.src = [pool.network(region)]; parent.tag = ""
        parent.negate_src = False
        parent.dst, parent.svc, parent.action = ["any"], ["any"], "inline"
        kids = []
        for _ in range(child_rules):
            b = rng.randrange(256)
            sub = [pool.network(f"10.{a}.{b}.0/24")] if rng.random() < 0.6 else [pool.host(f"10.{a}.{b}.{rng.randrange(1, 255)}")]
            kids.append(make_rule(rng, pool, opaque_frac, src=sub))
        explicit_cleanup = rng.random() < 0.5
        if explicit_cleanup:
            kids.append(Rule(0, ["any"], ["any"], ["any"], "drop", tag="cleanup")); kids[-1].inline = None
        for n, k in enumerate(kids, 1):
            k.num = n
        name = f"C{idx + 1}"
        parent.inline = name
        children[name] = {"rules": kids, "implicit": "drop" if explicit_cleanup else rng.choice(["drop", "accept"]),
                          "region": region}
    root.append(Rule(0, ["any"], ["any"], ["any"], "drop", tag="cleanup")); root[-1].inline = None
    for n, r in enumerate(root, 1):
        r.num = n
    return pool, root, children


def to_tree(pool, root, children):
    pl = payload(pool, root)
    for js, r in zip(pl["rulebase"], root):
        if r.inline:
            js["inline-layer"] = r.inline
    layers = [{"name": "L", "depth": 0, "path": "L", "display_prefix": "", "payload": pl}]
    for r in root:
        if r.inline:
            layers.append({"name": r.inline, "depth": 1, "path": f"L > {r.inline}", "display_prefix": str(r.num),
                           "parent_layer": "L", "parent_rule": r.num,
                           "payload": payload(pool, children[r.inline]["rules"])})
    return {"root_layer": "L", "root_layers": ["L"], "layers": layers}


def gateway(pool, root, children, s, d, p):
    """R82-style decision on hidden runtime values: ('rule', label, action) or ('implicit', layer, action)"""
    for r in root:
        if truth_match(pool, r, s, d, p):
            if r.inline:
                ch = children[r.inline]
                for k in ch["rules"]:
                    if truth_match(pool, k, s, d, p):
                        return ("rule", f"{r.num}.{k.num}", k.action)
                return ("implicit", r.inline, ch["implicit"])
            return ("rule", str(r.num), r.action)
    return ("implicit", "L", "drop")


def sample(rng, pool, root, children):
    k = rng.random()
    def pt(iv):
        a, b = rng.choice(iv); return rng.randint(a, b)
    def from_rule(r):
        S = dim_iv(pool, r.src, known=False); D = dim_iv(pool, r.dst, known=False); P = dim_iv(pool, r.svc, known=False, svc=True)
        s = pt(S) if not r.negate_src else rng.randint(int(ipaddress.ip_address("10.0.0.0")), int(ipaddress.ip_address("10.255.255.255")))
        return s, pt(D), pt(P)
    if k < 0.45 and children:
        name = rng.choice(sorted(children))
        ch = children[name]
        net = ipaddress.ip_network(ch["region"])
        if rng.random() < 0.8:
            s, d, p = from_rule(rng.choice(ch["rules"]))
            if not net.network_address._ip <= s <= net.broadcast_address._ip:
                s = rng.randint(int(net.network_address), int(net.broadcast_address))
            return s, d, p
        return (rng.randint(int(net.network_address), int(net.broadcast_address)),
                rng.randint(int(ipaddress.ip_address("10.0.0.0")), int(ipaddress.ip_address("10.255.255.255"))),
                rng.choice([443, 80, 22, 3389, rng.randrange(1, 65536)]))
    if k < 0.85:
        return from_rule(rng.choice([r for r in root if not r.inline]))
    return (rng.randint(int(ipaddress.ip_address("10.0.0.0")), int(ipaddress.ip_address("10.255.255.255"))),
            rng.randint(int(ipaddress.ip_address("10.0.0.0")), int(ipaddress.ip_address("10.255.255.255"))),
            rng.choice([443, 80, 22, 3389, rng.randrange(1, 65536)]))


def judge(o, gt):
    conf, matched = o.get("confidence"), o.get("matched")
    if matched and conf == "exact":
        w = o["winner"]
        claim = ("rule", str(w.get("display_rule")), str(w.get("action")).lower())
        return "correct" if (gt[0], gt[1], gt[2]) == claim else "wrong"
    if not matched and conf == "none" and o.get("result") == "No matching rule":
        return "correct" if gt[:2] == ("implicit", "L") else "wrong"
    if not matched and conf == "exact" and o.get("result") == "No final matching rule":
        layer = (o.get("path") or [{}])[-1].get("inline_layer")
        return "correct" if gt[:2] == ("implicit", layer) else "wrong"
    return "abstain"


def run(trace_access_tree, n_policies=30, opaque_frac=0.2, flows=400, seed=11):
    rng = random.Random(seed)
    C = Counter(); wrong_kinds = Counter()
    for _ in range(n_policies):
        pool, root, children = build(rng, opaque_frac=opaque_frac)
        tree = to_tree(pool, root, children)
        for _ in range(flows):
            s, d, p = sample(rng, pool, root, children)
            gt = gateway(pool, root, children, s, d, p)
            proto, q = query(p)
            o = trace_access_tree(tree, str(ipaddress.ip_address(s)), str(ipaddress.ip_address(d)), proto, q, "L")
            v = judge(o, gt)
            C[v] += 1
            if v == "wrong":
                wrong_kinds[f"{o.get('result')}|{o.get('confidence')}|gt={gt[0]}"] += 1
    return {"policies": n_policies, "opaque_frac": opaque_frac, "flows": sum(C.values()),
            "counts": dict(C), "wrong_kinds": dict(wrong_kinds)}


if __name__ == "__main__":
    mod = importlib.import_module(TRAFFIC_MODULE)
    out = {}
    for frac in (0.1, 0.2, 0.3):
        out[str(frac)] = run(mod.trace_access_tree, opaque_frac=frac)
        print(json.dumps(out[str(frac)]))
    tag = TRAFFIC_MODULE.split(".")[-1]
    json.dump(out, open(f"e2_inline_{tag}.json", "w"), indent=1)
