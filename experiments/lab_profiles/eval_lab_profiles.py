"""
E4 - evaluate Firewall Insight on the seeded lab profiles through the REAL
Management API, using the tool's own read-only client and hydration path.

Run after seed_lab_profiles.py (repo root):
  .venv\\Scripts\\python experiments\\lab_profiles\\eval_lab_profiles.py
Writes experiments/lab_profiles/results_lab.json
"""
from __future__ import annotations
import asyncio, json, sys, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))
from app.checkpoint import CheckPointClient          # noqa: E402  (read-only client)
from app.policy import hydrate_rulebase               # noqa: E402
from app.analyzer import analyze_rulebase             # noqa: E402
from app.traffic import trace_access_tree, trace_access   # noqa: E402


async def one(c, gt):
    layer = gt["layer"]
    t0 = time.perf_counter()
    tree = await c.show_rulebase_tree(layer)
    t1 = time.perf_counter()
    for node in tree.get("layers", []):
        node["payload"], _ = await hydrate_rulebase(c, node["payload"])
    t2 = time.perf_counter()
    root = next(n for n in tree["layers"] if int(n.get("depth", 0) or 0) == 0)
    out = analyze_rulebase(root["payload"])
    t3 = time.perf_counter()
    rep = {f["rule"]: f for f in out["findings"]["shadowing"]}
    C = {}
    cls_ok = cov_ok = 0
    for k, (lab, first, cls) in gt["labels"].items():
        num = int(k); hit = num in rep
        C[f"{lab}|{hit}"] = C.get(f"{lab}|{hit}", 0) + 1
        if lab == "covered" and hit:
            cls_ok += rep[num]["classification"] == cls
            cov_ok += rep[num]["covered_by"] == first
    tp = C.get("covered|True", 0); fn = C.get("covered|False", 0)
    fp = sum(v for kk, v in C.items() if kk.endswith("|True") and not kk.startswith("covered"))
    broad_pred = set(out["findings"]["any_any_any_rule_numbers"]); broad_gt = set(gt["any_any_any"])
    # flows: tri-state vs two-state against the ground-truth gateway decision
    F3 = {"correct": 0, "wrong": 0, "abstain": 0}; F2 = {"correct": 0, "wrong": 0}
    tf = []
    for f in gt["flows"]:
        q = {"atoms": [(f["proto"], f["port"], f["port"])], "protocol": f["proto"], "port": f["port"], "display": ""}
        s = time.perf_counter()
        o = trace_access_tree(tree, f["src"], f["dst"], f["proto"], q, root["name"])
        tf.append(time.perf_counter() - s)
        if o.get("matched") and o.get("confidence") == "exact":
            w = o["winner"]; ok = w["rule"] == f["gt_rule"] and w["action"].lower() == f["gt_action"]
            F3["correct" if ok else "wrong"] += 1
        elif not o.get("matched") and o.get("confidence") == "none":
            F3["correct" if f["gt_rule"] is None else "wrong"] += 1
        else:
            F3["abstain"] += 1
        o2 = trace_access(root["payload"], f["src"], f["dst"], f["proto"], q)
        ok2 = (o2["winner"]["rule"] == f["gt_rule"] and o2["winner"]["action"].lower() == f["gt_action"]) if o2["matched"] else f["gt_rule"] is None
        F2["correct" if ok2 else "wrong"] += 1
    return {"package": gt["package"], "rules": gt["rules"], "objects": gt["objects"],
            "rules_fetched": out["summary"]["total_rules"],
            "fetch_s": round(t1 - t0, 2), "hydrate_s": round(t2 - t1, 2), "analyze_s": round(t3 - t2, 3),
            "counts": C, "TP": tp, "FN": fn, "FP": fp,
            "precision": tp / (tp + fp) if tp + fp else None, "recall": tp / (tp + fn) if tp + fn else None,
            "class_agreement": cls_ok / tp if tp else None, "coverer_agreement": cov_ok / tp if tp else None,
            "any_any_any": {"TP": len(broad_pred & broad_gt), "FP": len(broad_pred - broad_gt), "FN": len(broad_gt - broad_pred)},
            "flows_tristate": F3, "flows_twostate": F2,
            "trace_ms_median": round(sorted(tf)[len(tf) // 2] * 1000, 2) if tf else None,
            "data_quality_truncated": bool(getattr(c, "hydration_truncated", False))}


async def main():
    files = sorted(HERE.glob("ground_truth_P*.json"))
    if not files:
        sys.exit("run seed_lab_profiles.py first")
    c = CheckPointClient()
    res = []
    try:
        info = await c.login()
        for f in files:
            gt = json.loads(f.read_text(encoding="utf-8"))
            r = await one(c, gt); res.append(r)
            print(json.dumps({k: r[k] for k in ("package", "rules", "TP", "FN", "FP", "precision", "recall", "fetch_s", "hydrate_s", "analyze_s", "flows_tristate", "flows_twostate")}))
    finally:
        await c.close()
    (HERE / "results_lab.json").write_text(json.dumps({"api_server_version": info.get("api-server-version"), "results": res}, indent=1), encoding="utf-8")
    print("wrote", HERE / "results_lab.json")

asyncio.run(main())
