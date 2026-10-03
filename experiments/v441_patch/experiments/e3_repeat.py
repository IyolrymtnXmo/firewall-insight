"""E3 (repeatability) - one warm-up run, then R timed runs of analyze_rulebase per size.
Reports every sample so dispersion can be shown (C003)."""
import random, time, json, sys, statistics, platform, os
sys.path.insert(0, '.')
from e1_anomaly import make_policy
from gen import payload
from app.analyzer import analyze_rulebase
from app.traffic import trace_access_tree
out = []
for N, R in ((100, 5), (250, 5), (500, 5), (1000, 5), (2000, 3)):
    rng = random.Random(N)
    pool, rules = make_policy(rng, n_base=N, k_pair=N // 10, k_comp=N // 50, k_und=N // 50, k_empty=1)
    pl = payload(pool, rules)
    analyze_rulebase(pl)                                   # warm-up (not timed)
    ts = []
    for _ in range(R):
        t = time.perf_counter(); analyze_rulebase(pl); ts.append(time.perf_counter() - t)
    tree = {"root_layer": "L", "root_layers": ["L"], "layers": [{"name": "L", "depth": 0, "path": "L", "display_prefix": "", "payload": pl}]}
    tt = []
    for _ in range(200):
        s = f"10.{rng.randrange(256)}.{rng.randrange(256)}.{rng.randrange(1,255)}"; d = f"10.{rng.randrange(256)}.{rng.randrange(256)}.{rng.randrange(1,255)}"
        t = time.perf_counter(); trace_access_tree(tree, s, d, "tcp", {"atoms": [("tcp", 443, 443)], "protocol": "tcp", "port": 443}, "L"); tt.append(time.perf_counter() - t)
    r = {"rules": len(rules), "runs": R, "analyze_samples_s": ts, "analyze_median_s": statistics.median(ts),
         "analyze_mean_s": statistics.mean(ts), "analyze_sd_s": statistics.stdev(ts) if R > 1 else 0.0,
         "trace_median_ms": statistics.median(tt) * 1000, "trace_p95_ms": sorted(tt)[int(0.95 * len(tt))] * 1000}
    print(json.dumps(r), flush=True); out.append(r)
json.dump({"cpu": platform.machine(), "python": platform.python_version(), "nproc": os.cpu_count(), "results": out},
          open('e3_repeat_results.json', 'w'), indent=1)
