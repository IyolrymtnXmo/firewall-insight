"""E3m - extra analysis time of the v4.43 multi-rule check (same policies as E3)."""
import random, time, json, sys, statistics, platform
sys.path.insert(0, sys.argv[1])
from e1_anomaly import make_policy
from gen import payload
from app.analyzer import analyze_rulebase
out = []
for N, R in ((100, 3), (250, 3), (500, 3), (1000, 3), (2000, 1)):
    rng = random.Random(N)
    pool, rules = make_policy(rng, n_base=N, k_pair=N // 10, k_comp=N // 50, k_und=N // 50, k_empty=1)
    pl = payload(pool, rules)
    res = {}
    for flag in (False, True):
        analyze_rulebase(pl, multi_rule=flag)
        ts = []
        for _ in range(R):
            t = time.perf_counter(); o = analyze_rulebase(pl, multi_rule=flag); ts.append(time.perf_counter() - t)
        res["multi" if flag else "pairwise"] = statistics.median(ts)
        if flag:
            res["multi_found"] = o["summary"]["multi_rule_shadowed"]; res["gave_up"] = o["summary"]["multi_rule_gave_up"]
    r = {"rules": len(rules), "runs": R, **res}
    print(json.dumps(r), flush=True); out.append(r)
json.dump({"python": platform.python_version(), "results": out}, open('e3_multi_results.json', 'w'), indent=1)
