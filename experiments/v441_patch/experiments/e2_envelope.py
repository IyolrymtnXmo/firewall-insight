"""E2c / E1c - does the prototype enforce its own supported-policy envelope?

Rules are narrowed by Time, Content or Install On, which neither analysis
models. The gateway model knows, per connection, whether the time window is
active and whether the connection carries the data type, and that the traced
gateway is GW-A. Everything else is statically evaluable, so any wrong
definite answer comes from the unmodelled columns alone.

usage: python e2_envelope.py <path-to-app-parent> <label>
"""
from __future__ import annotations
import sys, random, ipaddress, json, importlib
from collections import Counter
APPDIR, LABEL = sys.argv[1], sys.argv[2]
sys.path.insert(0, APPDIR)            # the app/ under test comes first
sys.path.insert(1, "/home/claude/exp")
traffic = importlib.import_module("app.traffic")
analyzer = importlib.import_module("app.analyzer")
from gen import Pool, Rule, payload, dim_iv
from e1_anomaly import rand_addr, rand_svc, pick, make_policy, dims, cover_state
from e2_tristate import query

EXTRA_OBJS = [{"uid": "pt", "name": "Policy Targets", "type": "Global"},
              {"uid": "work", "name": "Work-Hours", "type": "time"},
              {"uid": "pii", "name": "PII", "type": "data-type"},
              {"uid": "gwa", "name": "GW-A", "type": "simple-gateway"},
              {"uid": "gwb", "name": "GW-B", "type": "simple-gateway"}]

def decorate(pl, rules):
    for js, r in zip(pl["rulebase"], rules):
        js["time"] = ["work" if r.env == "time" else "any"]
        js["content"] = ["pii" if r.env == "content" else "any"]
        js["install-on"] = [r.inst] if r.env == "install" else ["pt"]
    pl["objects-dictionary"] = pl["objects-dictionary"] + EXTRA_OBJS
    return pl

def env_holds(r, flow_env):
    if r.env == "time":
        return flow_env["time_active"]
    if r.env == "content":
        return flow_env["has_pii"]
    if r.env == "install":
        return r.inst == "gwa"
    return True

def match3(pool, r, s, d, p):
    S = dim_iv(pool, r.src, known=False); D = dim_iv(pool, r.dst, known=False); P = dim_iv(pool, r.svc, known=False, svc=True)
    inside = lambda iv, x: any(a <= x <= b for a, b in iv)
    return inside(S, s) and inside(D, d) and inside(P, p)

def e2c(frac, n_pol=30, n_rules=40, flows=400, seed=13):
    rng = random.Random(seed); C = Counter()
    for _ in range(n_pol):
        pool = Pool(rng); rules = []
        for _ in range(n_rules):
            r = Rule(0, pick(rng, rand_addr, pool), pick(rng, rand_addr, pool), pick(rng, rand_svc, pool),
                     "accept" if rng.random() < 0.7 else "drop")
            r.env = rng.choice(["time", "content", "install"]) if rng.random() < frac else ""
            r.inst = rng.choice(["gwa", "gwb"])
            rules.append(r)
        cl = Rule(0, ["any"], ["any"], ["any"], "drop", tag="cleanup"); cl.env = ""; cl.inst = "gwa"; rules.append(cl)
        for n, r in enumerate(rules, 1): r.num = n
        pl = decorate(payload(pool, rules), rules)
        tree = {"root_layer": "L", "root_layers": ["L"], "layers": [{"name": "L", "depth": 0, "path": "L", "display_prefix": "", "payload": pl}]}
        for _ in range(flows):
            if rng.random() < 0.8:
                r = rng.choice(rules[:-1])
                S = dim_iv(pool, r.src, known=False); D = dim_iv(pool, r.dst, known=False); P = dim_iv(pool, r.svc, known=False, svc=True)
                pt = lambda iv: rng.randint(*rng.choice(iv))
                s, d, p = pt(S), pt(D), pt(P)
            else:
                lo, hi = int(ipaddress.ip_address("10.0.0.0")), int(ipaddress.ip_address("10.255.255.255"))
                s, d, p = rng.randint(lo, hi), rng.randint(lo, hi), rng.choice([443, 80, 22, rng.randrange(1, 65536)])
            fe = {"time_active": rng.random() < 0.5, "has_pii": rng.random() < 0.5}
            gt = next(((r.num, r.action) for r in rules if match3(pool, r, s, d, p) and env_holds(r, fe)), (None, "drop"))
            proto, q = query(p)
            o = traffic.trace_access_tree(tree, str(ipaddress.ip_address(s)), str(ipaddress.ip_address(d)), proto, q, "L")
            if o.get("matched") and o.get("confidence") == "exact":
                w = o["winner"]; C["correct" if (w["rule"], str(w["action"]).lower()) == gt else "wrong"] += 1
            elif not o.get("matched") and o.get("confidence") == "none":
                C["correct" if gt[0] is None else "wrong"] += 1
            else:
                C["abstain"] += 1
    n = sum(C.values())
    return {"frac": frac, "flows": n, "W": 100 * C["wrong"] / n, "A": 100 * C["abstain"] / n, "counts": dict(C)}

def e1c(n_pol=30, seed=2569, frac=0.2):
    """pairwise shadowing when 20% of rules carry a Time window"""
    rng = random.Random(seed); TP = FP = FN = 0
    for _ in range(n_pol):
        pool, rules = make_policy(rng, n_base=40)
        for r in rules:
            r.env = "time" if rng.random() < frac else ""; r.inst = "gwa"
        ds = [dims(pool, r) for r in rules]
        truth = set()
        for j in range(len(rules)):
            for i in range(j):
                if rules[i].env:                      # a time-limited rule covers nothing outside its window
                    continue
                st = cover_state(pool, ds[i], ds[j], rules[i], rules[j])
                if all(x is True for x in st):
                    truth.add(rules[j].num); break
        pl = decorate(payload(pool, rules), rules)
        rep = {s["rule"] for s in analyzer.analyze_rulebase(pl)["findings"]["shadowing"]}
        TP += len(rep & truth); FP += len(rep - truth); FN += len(truth - rep)
    return {"TP": TP, "FP": FP, "FN": FN, "precision": TP / (TP + FP) if TP + FP else None, "recall": TP / (TP + FN) if TP + FN else None}

if __name__ == "__main__":
    out = {"label": LABEL, "e2c": [e2c(f) for f in (0.1, 0.2, 0.3)], "e1c": e1c()}
    print(json.dumps(out))
    json.dump(out, open(f"e2_envelope_{LABEL}.json", "w"), indent=1)
