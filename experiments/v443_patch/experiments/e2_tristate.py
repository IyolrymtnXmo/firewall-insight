"""E2 - is the tri-state simulator sound?  Compare app.traffic.trace_access_tree
(tri-state, v4.39) with app.traffic.trace_access (the two-state first-match
tracer kept in the code base for compatibility) against a ground-truth gateway
model that knows the runtime value of every opaque object.
"""
from __future__ import annotations
import ipaddress, random, sys, json
from collections import Counter
sys.path.insert(0, ".")
from gen import Pool, Rule, payload, dim_iv, merge, contains, ADDR_MAX, SVC_MAX
from e1_anomaly import rand_addr, rand_svc, pick
from app.traffic import trace_access_tree, trace_access

def opaque_rule(rng, pool, rules):
    """a rule containing one element the static simulator cannot evaluate"""
    kind = rng.choice(["zone", "dynobj", "negate", "dcerpc", "group-mixed"])
    src = pick(rng, rand_addr, pool); dst = pick(rng, rand_addr, pool); svc = pick(rng, rand_svc, pool)
    neg = False
    hidden = lambda: [f"10.{rng.randrange(256)}.{rng.randrange(256)}.0/24" for _ in range(rng.randint(1, 3))]
    if kind == "zone":
        src = [pool.opaque_addr("security-zone", hidden())]
    elif kind == "dynobj":
        dst = [pool.opaque_addr("dynamic-object", hidden())]
    elif kind == "negate":
        neg = True
    elif kind == "dcerpc":
        svc = [pool.dcerpc()]
    else:  # a group mixing a normal member and a dynamic object
        src = [pool.group([rand_addr(rng, pool), pool.opaque_addr("dynamic-object", hidden())])]
    return Rule(0, src, dst, svc, "accept" if rng.random() < 0.7 else "drop", negate_src=neg, tag=kind)

def truth_match(pool, r, s, d, p):
    S = dim_iv(pool, r.src, known=False); D = dim_iv(pool, r.dst, known=False); P = dim_iv(pool, r.svc, known=False, svc=True)
    ms = contains(S, s)
    if r.negate_src:
        ms = not ms
    return ms and contains(D, d) and contains(P, p)

def gateway(pool, rules, s, d, p):
    for r in rules:
        if truth_match(pool, r, s, d, p):
            return (r.num, r.action)
    return (None, "drop")          # implicit cleanup

def sample_flow(rng, pool, rules):
    if rng.random() < 0.8:
        r = rng.choice(rules)
        S = dim_iv(pool, r.src, known=False); D = dim_iv(pool, r.dst, known=False); P = dim_iv(pool, r.svc, known=False, svc=True)
        def pt(iv):
            a, b = rng.choice(iv); return rng.randint(a, b)
        s = pt(S) if not r.negate_src else rng.randint(int(ipaddress.ip_address("10.0.0.0")), int(ipaddress.ip_address("10.255.255.255")))
        return s, pt(D), pt(P)
    return (rng.randint(int(ipaddress.ip_address("10.0.0.0")), int(ipaddress.ip_address("10.255.255.255"))),
            rng.randint(int(ipaddress.ip_address("10.0.0.0")), int(ipaddress.ip_address("10.255.255.255"))),
            rng.choice([443, 80, 22, 3389, 65536 + 53, rng.randrange(1, 65536)]))

def query(p):
    proto = "tcp" if p < 65536 else "udp"
    port = p if p < 65536 else p - 65536
    return proto, {"atoms": [(proto, port, port)], "protocol": proto, "port": port, "display": f"{proto}/{port}"}

def run(n_policies=30, n_rules=40, opaque_frac=0.2, flows=400, seed=7):
    rng = random.Random(seed)
    C3 = Counter(); C2 = Counter(); abst_detail = Counter()
    for _ in range(n_policies):
        pool = Pool(rng)
        rules = []
        for _ in range(n_rules):
            if rng.random() < opaque_frac:
                rules.append(opaque_rule(rng, pool, rules))
            else:
                rules.append(Rule(0, pick(rng, rand_addr, pool), pick(rng, rand_addr, pool), pick(rng, rand_svc, pool),
                                  "accept" if rng.random() < 0.7 else "drop"))
        rules.append(Rule(0, ["any"], ["any"], ["any"], "drop", tag="cleanup"))
        for n, r in enumerate(rules, 1):
            r.num = n
        pl = payload(pool, rules)
        tree = {"root_layer": "L", "root_layers": ["L"],
                "layers": [{"name": "L", "depth": 0, "path": "L", "display_prefix": "", "payload": pl}]}
        for _ in range(flows):
            s, d, p = sample_flow(rng, pool, rules)
            gt_rule, gt_act = gateway(pool, rules, s, d, p)
            proto, q = query(p)
            src, dst = str(ipaddress.ip_address(s)), str(ipaddress.ip_address(d))
            # --- tri-state (v4.39)
            o = trace_access_tree(tree, src, dst, proto, q, "L")
            if o.get("matched") and o.get("confidence") == "exact":
                w = o["winner"]; ok = (w["rule"] == gt_rule and w["action"].lower() == gt_act)
                C3["correct" if ok else "wrong"] += 1
            elif not o.get("matched") and o.get("confidence") == "none":
                ok = gt_rule is None
                C3["correct" if ok else "wrong"] += 1
            else:
                C3["abstain"] += 1
                pw = (o.get("possible_winner") or {}).get("rule")
                abst_detail["abstain_gt_is_possible_winner" if pw == gt_rule else "abstain_gt_is_other"] += 1
            # --- two-state baseline
            o2 = trace_access(pl, src, dst, proto, q)
            if o2["matched"]:
                w = o2["winner"]; ok = (w["rule"] == gt_rule and w["action"].lower() == gt_act)
            else:
                ok = gt_rule is None
            C2["correct" if ok else "wrong"] += 1
    tot = sum(C3.values())
    return {"policies": n_policies, "rules_per_policy": n_rules + 1, "opaque_frac": opaque_frac, "flows": tot,
            "tristate": {k: C3[k] for k in ("correct", "wrong", "abstain")},
            "twostate": {k: C2[k] for k in ("correct", "wrong")},
            "abstain_detail": dict(abst_detail)}

if __name__ == "__main__":
    out = {}
    for frac in (0.1, 0.2, 0.3):
        out[str(frac)] = run(opaque_frac=frac)
        print(json.dumps(out[str(frac)]))
    json.dump(out, open("e2_results.json", "w"), indent=1)
