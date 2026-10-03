"""E1 - seeded-anomaly detection accuracy of app.analyzer.analyze_rulebase.

Ground truth comes from the independent oracle in this file (interval sets,
exact 3-D union coverage on an elementary-interval grid), not from the labels
used while seeding, so accidental anomalies in the random base policy are
scored too.
"""
from __future__ import annotations
import ipaddress, random, json, sys, statistics, itertools
from collections import Counter
sys.path.insert(0, ".")
from gen import Pool, Rule, payload, dim_iv, merge, subset, ADDR_MAX, SVC_MAX
from app.analyzer import analyze_rulebase

COMMON_TCP = [22, 80, 443, 3389, 445, 389, 636, 8080, 1433, 3306, 25, 110]
COMMON_UDP = [53, 123, 161, 514, 1812]

def rand_net(rng, pool, prefix=None):
    a, b = rng.randrange(0, 256), rng.randrange(0, 256)
    prefix = prefix or rng.choice([16, 24, 24, 24, 28])
    base = ipaddress.ip_network(f"10.{a}.{b}.0/24")
    if prefix == 16:
        base = ipaddress.ip_network(f"10.{a}.0.0/16")
    elif prefix == 28:
        base = ipaddress.ip_network(f"10.{a}.{b}.{rng.randrange(0,16)*16}/28")
    return pool.network(str(base))

def rand_addr(rng, pool):
    k = rng.random()
    if k < 0.45:
        return rand_net(rng, pool)
    if k < 0.75:
        return pool.host(f"10.{rng.randrange(256)}.{rng.randrange(256)}.{rng.randrange(1,255)}")
    if k < 0.85:
        a, b = rng.randrange(256), rng.randrange(256)
        s = rng.randrange(1, 200)
        return pool.arange(f"10.{a}.{b}.{s}", f"10.{a}.{b}.{s + rng.randrange(1, 50)}")
    return pool.group([rand_addr(rng, pool) for _ in range(rng.randrange(2, 4))])

def rand_svc(rng, pool):
    k = rng.random()
    if k < 0.6:
        return pool.svc("tcp", rng.choice(COMMON_TCP))
    if k < 0.75:
        return pool.svc("udp", rng.choice(COMMON_UDP))
    if k < 0.9:
        lo = rng.randrange(1024, 60000)
        return pool.svc("tcp", lo, lo + rng.randrange(10, 2000))
    return pool.group([rand_svc(rng, pool) for _ in range(2)], typ="service-group")

def pick(rng, f, pool, lo=1, hi=2):
    return [f(rng, pool) for _ in range(rng.randint(lo, hi))]

def sub_addr(rng, pool, uids):
    """object(s) whose address set is inside the union of `uids`"""
    if uids == ["any"]:
        return pick(rng, rand_addr, pool, 1, 1)
    iv = dim_iv(pool, uids)
    s, e = rng.choice(iv)
    mode = rng.random()
    if mode < 0.2:
        return [rng.choice(uids)]                 # same UID
    if mode < 0.5 or e - s < 16:
        v = rng.randint(s, e)
        return [pool.host(str(ipaddress.ip_address(v)))]
    if mode < 0.8:
        # largest aligned sub-network inside [s,e]
        for pl in (28, 29, 30):
            size = 2 ** (32 - pl)
            start = ((s + size - 1) // size) * size
            if start + size - 1 <= e:
                return [pool.network(f"{ipaddress.ip_address(start)}/{pl}")]
        v = rng.randint(s, e)
        return [pool.host(str(ipaddress.ip_address(v)))]
    a = rng.randint(s, e); b = rng.randint(a, e)
    return [pool.group([pool.host(str(ipaddress.ip_address(a))), pool.host(str(ipaddress.ip_address(b)))])]

def sub_svc(rng, pool, uids):
    if uids == ["any"]:
        return pick(rng, rand_svc, pool, 1, 1)
    iv = dim_iv(pool, uids, svc=True)
    s, e = rng.choice(iv)
    if rng.random() < 0.3:
        return [rng.choice(uids)]
    v = rng.randint(s, e)
    proto = "tcp" if v < 65536 else "udp"
    return [pool.svc(proto, v - (0 if proto == "tcp" else 65536))]

# ---------------------------------------------------------------- oracle
def dims(pool, r):
    return (dim_iv(pool, r.src), dim_iv(pool, r.dst), dim_iv(pool, r.svc, svc=True))

def cover_state(pool, ei, ej, earlier, later):
    """per-dimension: True / False / None(unknown)"""
    out = []
    ru_i = (earlier.src, earlier.dst, earlier.svc); ru_j = (later.src, later.dst, later.svc)
    for k, (a, b) in enumerate(zip(ei, ej)):
        full = [(0, SVC_MAX)] if k == 2 else [(0, ADDR_MAX)]
        if not ru_j[k]:                             # empty field: no data, never provable
            out.append(None); continue
        if ru_i[k] == ["any"] or set(ru_j[k]) <= set(ru_i[k]):
            out.append(True); continue              # Any / same object covers even opaque values
        if b is None:                               # empty or opaque later side
            out.append(None); continue
        if a is None:
            out.append(None); continue
        out.append(subset(b, a))
    return out

def union_covered(j_d, earlier_ds):
    """exact test: is box-union j (product of interval unions) inside union of earlier boxes"""
    rel = [d for d in earlier_ds if all(x is not None for x in d)]
    if not rel:
        return False
    cuts = []
    for k in range(3):
        pts = set()
        for s, e in j_d[k]:
            pts.add(s); pts.add(e + 1)
        for d in rel:
            for s, e in d[k]:
                pts.add(s); pts.add(e + 1)
        pts = sorted(pts)
        cells = []
        for a, b in zip(pts, pts[1:]):
            if any(s <= a and b - 1 <= e for s, e in j_d[k]):
                cells.append(a)
        cuts.append(cells)
    for x in cuts[0]:
        for y in cuts[1]:
            for z in cuts[2]:
                if not any(any(s <= x <= e for s, e in d[0]) and any(s <= y <= e for s, e in d[1]) and any(s <= z <= e for s, e in d[2]) for d in rel):
                    return False
    return True

def truth(pool, rules):
    ds = [dims(pool, r) for r in rules]
    labels = {}
    for j, rj in enumerate(rules):
        first = None; undecidable = False
        for i in range(j):
            st = cover_state(pool, ds[i], ds[j], rules[i], rj)
            if all(x is True for x in st):
                first = i; break
            if all(x in (True, None) for x in st) and any(x is None for x in st):
                undecidable = True
        if first is not None:
            cls = "Redundant" if rules[first].action == rj.action else "Shadowed / action conflict"
            labels[rj.num] = ("covered", rules[first].num, cls)
        elif undecidable or any(x is None for x in ds[j]):
            labels[rj.num] = ("undecidable", None, None)
        elif j > 0 and union_covered(ds[j], ds[:j]):
            labels[rj.num] = ("compound", None, None)
        else:
            labels[rj.num] = ("clean", None, None)
    return labels

# ---------------------------------------------------------------- generator
def make_policy(rng, n_base=40, k_pair=8, k_comp=3, k_und=3, k_empty=1, broad=True):
    pool = Pool(rng)
    rules = []
    for _ in range(n_base):
        src = pick(rng, rand_addr, pool) if rng.random() > 0.05 else ["any"]
        dst = pick(rng, rand_addr, pool) if rng.random() > 0.05 else ["any"]
        svc = pick(rng, rand_svc, pool) if rng.random() > 0.05 else ["any"]
        rules.append(Rule(0, src, dst, svc, "accept" if rng.random() < 0.8 else "drop"))
    seeds = []
    for _ in range(k_pair):
        i = rng.randrange(len(rules))
        ri = rules[i]
        rj = Rule(0, sub_addr(rng, pool, ri.src), sub_addr(rng, pool, ri.dst), sub_svc(rng, pool, ri.svc),
                  ri.action if rng.random() < 0.5 else ("drop" if ri.action == "accept" else "accept"), tag="seed-pair")
        pos = rng.randint(i + 1, len(rules))
        rules.insert(pos, rj)
    for _ in range(k_comp):
        a, b = rng.randrange(256), rng.randrange(256)
        lo = pool.network(f"10.{a}.{b}.0/25"); hi = pool.network(f"10.{a}.{b}.128/25")
        dst = pick(rng, rand_addr, pool, 1, 1); svc = pick(rng, rand_svc, pool, 1, 1)
        act = rng.choice(["accept", "accept", "drop"])
        r1 = Rule(0, [lo], dst, svc, act, tag="seed-comp-part"); r2 = Rule(0, [hi], dst, svc, act, tag="seed-comp-part")
        if rng.random() < 0.5:
            jsrc = [pool.network(f"10.{a}.{b}.0/24")]
        else:
            jsrc = [pool.group([pool.host(f"10.{a}.{b}.{rng.randrange(1,127)}"), pool.host(f"10.{a}.{b}.{rng.randrange(129,255)}")])]
        rj = Rule(0, jsrc, sub_addr(rng, pool, dst), sub_svc(rng, pool, svc), act, tag="seed-comp")
        p1 = rng.randint(0, len(rules)); rules.insert(p1, r1)
        p2 = rng.randint(0, len(rules)); rules.insert(p2, r2)
        p3 = rng.randint(max(rules.index(r1), rules.index(r2)) + 1, len(rules)); rules.insert(p3, rj)
    for _ in range(k_und):
        cand = [x for x in rules if x.src != ["any"] and dim_iv(pool, x.src) is not None]
        ri = rng.choice(cand); i = rules.index(ri)
        iv = dim_iv(pool, ri.src)
        s, e = rng.choice(iv)
        hidden = [str(ipaddress.ip_network(f"{ipaddress.ip_address(s)}/32"))]
        z = pool.opaque_addr(rng.choice(["security-zone", "dynamic-object"]), hidden)
        rj = Rule(0, [z], sub_addr(rng, pool, ri.dst), sub_svc(rng, pool, ri.svc), ri.action, tag="seed-und")
        rules.insert(rng.randint(i + 1, len(rules)), rj)
    for _ in range(k_empty):
        ri = rng.choice(rules); i = rules.index(ri)
        rj = Rule(0, [], sub_addr(rng, pool, ri.dst), sub_svc(rng, pool, ri.svc), ri.action, tag="seed-empty")
        rules.insert(rng.randint(i + 1, len(rules)), rj)
    if broad:
        rules.append(Rule(0, ["any"], ["any"], ["any"], "accept", tag="seed-broad"))
    rules.append(Rule(0, ["any"], ["any"], ["any"], "drop", tag="cleanup"))
    for n, r in enumerate(rules, 1):
        r.num = n
    return pool, rules

def run(n_policies=30, n_base=40, seed=2569):
    rng = random.Random(seed)
    C = Counter(); cls_ok = 0; cls_n = 0; cov_ok = 0
    broad_tp = broad_fp = broad_fn = 0
    for p in range(n_policies):
        pool, rules = make_policy(rng, n_base=n_base, broad=(p % 2 == 0))
        lab = truth(pool, rules)
        out = analyze_rulebase(payload(pool, rules))
        rep = {f["rule"]: f for f in out["findings"]["shadowing"]}
        for num, (t, first, cls) in lab.items():
            reported = num in rep
            C[(t, reported)] += 1
            if t == "covered" and reported:
                cls_n += 1
                cls_ok += rep[num]["classification"] == cls
                cov_ok += rep[num]["covered_by"] == first
        tb = {r.num for r in rules if r.src == ["any"] and r.dst == ["any"] and r.svc == ["any"] and not (r is rules[-1] and r.action == "drop")}
        pb = set(out["findings"]["any_any_any_rule_numbers"])
        broad_tp += len(tb & pb); broad_fp += len(pb - tb); broad_fn += len(tb - pb)
    tp = C[("covered", True)]; fn = C[("covered", False)]
    fp_clean = C[("clean", True)]; fp_und = C[("undecidable", True)]; fp_comp = C[("compound", True)]
    fp = fp_clean + fp_und + fp_comp
    prec = tp / (tp + fp) if tp + fp else float("nan"); rec = tp / (tp + fn) if tp + fn else float("nan")
    res = {
        "policies": n_policies, "n_base": n_base,
        "rules_total": sum(C.values()),
        "truth_counts": {t: C[(t, True)] + C[(t, False)] for t in ("covered", "compound", "undecidable", "clean")},
        "pairwise": {"TP": tp, "FN": fn, "FP": fp, "precision": prec, "recall": rec,
                     "F1": 2 * prec * rec / (prec + rec) if prec + rec else 0},
        "class_agreement": cls_ok / cls_n if cls_n else None,
        "covered_by_agreement": cov_ok / cls_n if cls_n else None,
        "compound_detected": C[("compound", True)], "compound_total": C[("compound", True)] + C[("compound", False)],
        "undecidable_reported": fp_und, "undecidable_total": C[("undecidable", True)] + C[("undecidable", False)],
        "clean_reported": fp_clean, "clean_total": C[("clean", True)] + C[("clean", False)],
        "any_any_any": {"TP": broad_tp, "FP": broad_fp, "FN": broad_fn},
    }
    return res

if __name__ == "__main__":
    allres = {}
    for nb in (40, 150):
        allres[nb] = run(n_policies=30, n_base=nb)
        print(json.dumps(allres[nb], indent=1))
    json.dump(allres, open("e1_results.json", "w"), indent=1)
