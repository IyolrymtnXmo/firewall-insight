"""E2e / E1e - are the object classes declared "definite" really fully modelled?

Rules use objects whose definition says more than the interval model keeps:

  srcport   TCP service restricted to source ports > 1023
  sig       TCP service matched by protocol signature
  icmpcode  ICMP service with a type and a code
  dual      host object with an IPv4 and an IPv6 address (queried over IPv6)

The gateway model knows the source port, whether the payload carries the
signature, the ICMP code and both address families. Everything else in the
policy is static, so a wrong definite answer comes from these objects alone.

usage: python e2e_scope.py <dir-containing-app/> <label>
"""
from __future__ import annotations
import sys, random, ipaddress, json, importlib
from collections import Counter
APPDIR, LABEL = sys.argv[1], sys.argv[2]
sys.path.insert(0, APPDIR)
traffic = importlib.import_module("app.traffic")
analyzer = importlib.import_module("app.analyzer")
from gen import Pool, Rule, Obj, payload, dim_iv
from e1_anomaly import rand_addr, rand_svc, pick

LO, HI = int(ipaddress.ip_address("10.0.0.0")), int(ipaddress.ip_address("10.255.255.255"))
V6 = int(ipaddress.ip_address("2001:db8::"))
ip = lambda n: str(ipaddress.ip_address(n))
KINDS = ["srcport", "sig", "icmpcode", "dual"]


def special(rng, pool, kind):
    """(uid, spec) - one object of the given kind; spec is the oracle's truth."""
    u = pool.uid("x")
    if kind == "srcport":
        port = rng.choice([443, 80, 22, 3389])
        js = {"uid": u, "name": f"tcp_{port}_src", "type": "service-tcp", "port": str(port), "source-port": ">1023"}
        spec = {"kind": kind, "port": port}
    elif kind == "sig":
        port = rng.choice([80, 8080, 443])
        js = {"uid": u, "name": f"sig_{port}", "type": "service-tcp", "port": str(port),
              "protocol": "HTTP", "match-by-protocol-signature": True}
        spec = {"kind": kind, "port": port}
    elif kind == "icmpcode":
        t, c = rng.choice([(3, 1), (3, 3), (11, 0), (5, 1)])
        js = {"uid": u, "name": f"icmp_{t}_{c}", "type": "service-icmp", "icmp-type": t, "icmp-code": c}
        spec = {"kind": kind, "type": t, "code": c}
    else:
        v4 = rng.randint(LO, HI); v6 = V6 + rng.randrange(1, 2 ** 16)
        js = {"uid": u, "name": f"dual_{u}", "type": "host", "ipv4-address": ip(v4), "ipv6-address": ip(v6)}
        spec = {"kind": kind, "v4": v4, "v6": v6}
    pool.add(Obj(u, js, None))
    return u, spec


def rule_match(pool, r, f):
    inside = lambda iv, x: any(a <= x <= b for a, b in iv)
    sp = getattr(r, "spec", None)
    # source
    if not f["v6"]:
        if not inside(dim_iv(pool, r.src, known=False), f["s"]):
            return False
    elif r.src != ["any"]:
        return False                                  # generated sources are IPv4 only
    # destination
    if sp and sp["kind"] == "dual":
        if not (f["d"] == (sp["v6"] if f["v6"] else sp["v4"])):
            return False
    elif f["v6"]:
        if r.dst != ["any"]:
            return False
    elif not inside(dim_iv(pool, r.dst, known=False), f["d"]):
        return False
    # service
    if sp and sp["kind"] == "srcport":
        return f["proto"] == "tcp" and f["port"] == sp["port"] and f["sport"] > 1023
    if sp and sp["kind"] == "sig":
        return f["proto"] == "tcp" and f["port"] == sp["port"] and f["http"]
    if sp and sp["kind"] == "icmpcode":
        return f["proto"] == "icmp" and f["port"] == sp["type"] and f["code"] == sp["code"]
    if r.svc == ["any"]:
        return True
    if f["proto"] == "icmp":
        return False
    return inside(dim_iv(pool, r.svc, known=False, svc=True), f["port"] + (0 if f["proto"] == "tcp" else 65536))


def make_rule(rng, pool, frac):
    r = Rule(0, pick(rng, rand_addr, pool), pick(rng, rand_addr, pool), pick(rng, rand_svc, pool),
             "accept" if rng.random() < 0.7 else "drop")
    r.spec = None
    if rng.random() < frac:
        kind = rng.choice(KINDS)
        u, spec = special(rng, pool, kind)
        r.spec = spec
        if kind == "dual":
            r.dst = [u]; r.src = ["any"]
        else:
            r.svc = [u]
    return r


def flow_for(rng, pool, r):
    """A connection aimed at rule r; the hidden attributes are drawn at random."""
    pt = lambda iv: rng.randint(*rng.choice(iv))
    f = {"v6": False, "sport": rng.choice([500, 1023, 1024, 40000, 51000]), "http": rng.random() < 0.5,
         "code": rng.choice([0, 1, 3])}
    sp = r.spec
    f["s"] = pt(dim_iv(pool, r.src, known=False)) if r.src != ["any"] else rng.randint(LO, HI)
    if sp and sp["kind"] == "dual":
        f["v6"] = rng.random() < 0.6
        f["d"] = sp["v6"] if f["v6"] else sp["v4"]
        if f["v6"]:
            f["s"] = V6 + rng.randrange(2 ** 16, 2 ** 20)
    else:
        f["d"] = pt(dim_iv(pool, r.dst, known=False))
    if sp and sp["kind"] in ("srcport", "sig"):
        f["proto"], f["port"] = "tcp", sp["port"]
    elif sp and sp["kind"] == "icmpcode":
        f["proto"], f["port"] = "icmp", sp["type"]
    elif r.svc == ["any"] or (sp and sp["kind"] == "dual" and r.svc == ["any"]):
        f["proto"], f["port"] = "tcp", rng.choice([443, 80, 22])
    else:
        p = pt(dim_iv(pool, r.svc, known=False, svc=True))
        f["proto"], f["port"] = ("tcp", p) if p < 65536 else ("udp", p - 65536)
    return f


def e2e(frac, n_pol=30, n_rules=40, flows=400, seed=23):
    rng = random.Random(seed); C = Counter()
    for _ in range(n_pol):
        pool = Pool(rng)
        rules = [make_rule(rng, pool, frac) for _ in range(n_rules)]
        cl = Rule(0, ["any"], ["any"], ["any"], "drop", tag="cleanup"); cl.spec = None; rules.append(cl)
        for n, r in enumerate(rules, 1):
            r.num = n
        pl = payload(pool, rules)
        tree = {"root_layer": "L", "root_layers": ["L"],
                "layers": [{"name": "L", "depth": 0, "path": "L", "display_prefix": "", "payload": pl}]}
        for _ in range(flows):
            f = flow_for(rng, pool, rng.choice(rules[:-1]))
            gt = next(((r.num, r.action) for r in rules if rule_match(pool, r, f)), (None, "drop"))
            q = {"atoms": [(f["proto"], f["port"], f["port"])], "protocol": f["proto"], "port": f["port"],
                 "display": f"{f['proto']}/{f['port']}"}
            o = traffic.trace_access_tree(tree, ip(f["s"]), ip(f["d"]), f["proto"], q, "L")
            if o.get("matched") and o.get("confidence") == "exact":
                w = o["winner"]
                C["correct" if (w["rule"], str(w["action"]).lower()) == gt else "wrong"] += 1
            elif not o.get("matched") and o.get("confidence") == "none":
                C["correct" if gt[0] is None else "wrong"] += 1
            else:
                C["abstain"] += 1
    n = sum(C.values())
    return {"frac": frac, "flows": n, "W": 100 * C["wrong"] / n, "A": 100 * C["abstain"] / n, "counts": dict(C)}


def e1e(n_pol=30, n_rules=40, frac=0.2, seed=2569):
    """Pairwise shadowing when 20% of the rules use a restricted service.

    Truth: a rule with a restricted service covers a later rule only when the
    later rule uses the very same object. Pairs between ordinary rules are
    taken from both versions' agreement on the same policy with the special
    rules removed, so only the pairs that involve a restricted service differ.
    """
    rng = random.Random(seed); TP = FP = FN = 0
    for _ in range(n_pol):
        pool = Pool(rng); rules = []
        for _ in range(n_rules):
            r = Rule(0, ["any"], pick(rng, rand_addr, pool), pick(rng, rand_svc, pool),
                     "accept" if rng.random() < 0.7 else "drop"); r.spec = None
            rules.append(r)
        # seed pairs: an earlier rule with a restricted service, then a later
        # rule on the same port without the restriction (NOT shadowed), and a
        # later rule that reuses the same object (shadowed).
        for _ in range(int(n_rules * frac / 2)):
            kind = rng.choice(["srcport", "sig", "icmpcode"])
            u, spec = special(rng, pool, kind)
            dst = pick(rng, rand_addr, pool)
            a = Rule(0, ["any"], dst, [u], "accept"); a.spec = spec
            if kind == "icmpcode":
                pu = pool.uid("x"); pool.add(Obj(pu, {"uid": pu, "name": f"icmp_{spec['type']}", "type": "service-icmp",
                                                    "icmp-type": spec["type"]}, None))
            else:
                pu = pool.svc("tcp", spec["port"])
            b = Rule(0, ["any"], dst, [pu], "drop"); b.spec = None; b.truth = False
            c = Rule(0, ["any"], dst, [u], "drop"); c.spec = spec; c.truth = True
            pos = rng.randrange(len(rules) + 1)
            rules[pos:pos] = [a, b, c]
        for n, r in enumerate(rules, 1):
            r.num = n
        pl = payload(pool, rules)
        rep = {s["rule"]: s["covered_by"] for s in analyzer.analyze_rulebase(pl)["findings"]["shadowing"]}
        for r in rules:
            if not hasattr(r, "truth"):
                continue
            said = r.num in rep
            if r.truth and said: TP += 1
            elif r.truth and not said: FN += 1
            elif not r.truth and said:
                # covered by an ordinary earlier rule is a true finding, not an error
                by = next(x for x in rules if x.num == rep[r.num])
                if by.spec is not None: FP += 1
    return {"TP": TP, "FP": FP, "FN": FN, "precision": TP / (TP + FP) if TP + FP else None,
            "recall": TP / (TP + FN) if TP + FN else None}


if __name__ == "__main__":
    out = {"label": LABEL, "e2e": [e2e(f) for f in (0.1, 0.2, 0.3)], "e1e": e1e()}
    print(json.dumps(out))
    json.dump(out, open(f"e2e_scope_{LABEL}.json", "w"), indent=1)
