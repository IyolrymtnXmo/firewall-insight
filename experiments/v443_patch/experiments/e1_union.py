"""E1u - recall against ALL unreachable rules, pairwise vs pairwise + multi-rule (v4.43).

Same 60 policies as E1 (seed 2569, bases 40 and 150). Two ground truths:

  provable   the E1 oracle labels: 'covered' (one earlier rule) + 'compound'
             (several earlier rules) - computed from the configured values
  dead       a rule no connection can reach at the gateway: union coverage on
             the TRUE values (hidden members of zones / dynamic objects
             included), using every earlier rule - the gateway model's view

The tool never sees hidden values, so 'dead' rules behind an opaque object
can only be missed, never found; they are reported separately.

usage: python e1_union.py <dir-containing-app/> <label>
"""
from __future__ import annotations
import sys, random, json
APPDIR, LABEL = sys.argv[1], sys.argv[2]
sys.path.insert(0, APPDIR)
from gen import payload, dim_iv
import e1_anomaly as E
from app.analyzer import analyze_rulebase


def true_dims(pool, r):
    return (dim_iv(pool, r.src, known=False), dim_iv(pool, r.dst, known=False),
            dim_iv(pool, r.svc, known=False, svc=True))


def _hits(a, b):
    return all(any(not (y1 < x0 or y0 > x1) for x0, x1 in a[k] for y0, y1 in b[k]) for k in range(3))


def oracle_dead(j_d, earlier):
    """E1 oracle's grid test, given only the earlier rules that overlap j (pruning
    cannot change the answer: a rule that misses j covers none of it)."""
    rel = [d for d in earlier if all(x is not None for x in d) and _hits(j_d, d)]
    # necessary condition, cheap: every projection of j must be covered by the
    # union of the earlier projections (fast reject before the 3-D grid)
    for k in range(3):
        u = E.merge([iv for d in rel for iv in d[k]]) if rel else []
        if not E.subset(j_d[k], u):
            return False
    return E.union_covered(j_d, rel)


def run(n_policies=30, n_base=40, seed=2569):
    rng = random.Random(seed)
    c = dict(prov=0, prov_pair=0, prov_all=0, comp=0, comp_found=0, dead=0, dead_pair=0, dead_all=0,
             rep_pair=0, rep_multi=0, fp_multi=0, gave_up=0, rules=0)
    for p in range(n_policies):
        pool, rules = E.make_policy(rng, n_base=n_base, broad=(p % 2 == 0))
        lab = E.truth(pool, rules)
        out = analyze_rulebase(payload(pool, rules))
        P = {f["rule"] for f in out["findings"]["shadowing"]}
        M = {f["rule"] for f in out["findings"].get("multi_rule_shadowing", [])}
        c["gave_up"] += out["summary"].get("multi_rule_gave_up", 0)
        td = [true_dims(pool, r) for r in rules]
        dead = set()
        for j, r in enumerate(rules):
            if j == 0 or any(x is None for x in td[j]):
                continue
            if lab[r.num][0] in ("covered", "compound") or oracle_dead(td[j], td[:j]):
                dead.add(r.num)
        prov = {n for n, (t, _a, _b) in lab.items() if t in ("covered", "compound")}
        comp = {n for n, (t, _a, _b) in lab.items() if t == "compound"}
        c["rules"] += len(rules)
        c["prov"] += len(prov); c["prov_pair"] += len(prov & P); c["prov_all"] += len(prov & (P | M))
        c["comp"] += len(comp); c["comp_found"] += len(comp & M)
        c["dead"] += len(dead); c["dead_pair"] += len(dead & P); c["dead_all"] += len(dead & (P | M))
        c["rep_pair"] += len(P); c["rep_multi"] += len(M)
        c["fp_multi"] += len(M - dead)
    r = lambda a, b: round(a / b, 4) if b else None
    c.update({
        "recall_provable_pairwise": r(c["prov_pair"], c["prov"]),
        "recall_provable_with_multi": r(c["prov_all"], c["prov"]),
        "recall_compound_multi": r(c["comp_found"], c["comp"]),
        "recall_dead_pairwise": r(c["dead_pair"], c["dead"]),
        "recall_dead_with_multi": r(c["dead_all"], c["dead"]),
        "precision_multi_vs_dead": r(c["rep_multi"] - c["fp_multi"], c["rep_multi"]),
    })
    return c


if __name__ == "__main__":
    res = {"label": LABEL}
    for nb in (40, 150):
        res[str(nb)] = run(n_base=nb)
    print(json.dumps(res, indent=1))
    json.dump(res, open(f"e1_union_{LABEL}.json", "w"), indent=1)
