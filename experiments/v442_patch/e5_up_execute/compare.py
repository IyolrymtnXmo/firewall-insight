"""E5 - score the filled-in CSV.

    python compare.py e5_compare_External-FW.csv

A row counts once `gateway_action` is filled in. The three numbers the paper
needs:

  definite and same action    the tool said exact and the gateway agrees
  definite and different      the tool said exact and the gateway disagrees  (W)
  not definite                the tool declined; the gateway's answer is shown
"""
from __future__ import annotations
import csv, json, sys


def main(path: str) -> None:
    rows = [r for r in csv.DictReader(open(path, encoding="utf-8-sig")) if r.get("gateway_action", "").strip()]
    out = {"cases_compared": len(rows), "definite_same": 0, "definite_different": 0, "not_definite": 0,
           "different": [], "not_definite_cases": []}
    for r in rows:
        tool, gw = r["tool_action"].strip().lower(), r["gateway_action"].strip().lower()
        if r["tool_confidence"].strip() == "exact":
            if gw and gw in tool:
                out["definite_same"] += 1
            else:
                out["definite_different"] += 1
                out["different"].append({"case": r["case"], "tool": tool, "gateway": gw, "gateway_rule": r["gateway_rule"]})
        else:
            out["not_definite"] += 1
            out["not_definite_cases"].append({"case": r["case"], "tool": tool, "confidence": r["tool_confidence"], "gateway": gw})
    json.dump(out, open(path.replace(".csv", "_result.json"), "w"), indent=1, ensure_ascii=False)
    print(json.dumps(out, indent=1, ensure_ascii=False))


if __name__ == "__main__":
    main(sys.argv[1])
