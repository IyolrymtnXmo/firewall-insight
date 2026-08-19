"""CSV exports of the raw policy and of the analysis."""

from __future__ import annotations

import csv
import io

from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse

from ..inline_layers import aggregate_browser
from ..policy import access_tree, analyze_layer
from ..policy_browser import browse_access_rulebase
from ..runtime import cache_get, cache_set, use_client

router = APIRouter()


@router.get("/api/policy-browser.csv")
async def policy_browser_csv(layer: str = Query(...)):
    data = await use_client(
        lambda c: _policy_browser_for_export(c, layer)
    )
    s = io.StringIO()
    w = csv.writer(s)
    w.writerow([
        "Layer", "Layer Path", "Parent Rule", "Rule", "Section", "Name", "Enabled", "Source", "Destination",
        "VPN", "Service", "Action", "Track", "Install On", "Time",
        "Inline Layer", "Comments", "Hits", "Last Hit"
    ])
    for r in data["rules"]:
        w.writerow([
            r.get("layer"), r.get("layer_path"), r.get("parent_rule"), r["rule"], r["section"], r["name"], r["enabled"], r["source"],
            r["destination"], r["vpn"], r["service"], r["action"], r["track"],
            r["install_on"], r["time"], r["inline_layer"], r["comments"],
            r["hits"], r["last_hit"]
        ])
    return StreamingResponse(
        iter([s.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition":
                f'attachment; filename="{layer.replace(" ", "_")}_raw_policy.csv"'
        },
    )

async def _policy_browser_for_export(c, layer):
    key = f"policy-browser:{layer}"
    cached = cache_get(key)
    if cached is not None:
        return cached
    tree = await access_tree(c, layer, hydrate=False)
    browsed = [browse_access_rulebase(node["payload"]) for node in tree.get("layers", [])]
    result = aggregate_browser(tree, browsed)
    cache_set(key, result)
    return result

@router.get("/api/export.csv")
async def export_csv(layer: str = Query(...)):
    data = await use_client(lambda c: analyze_layer(c, layer))
    s = io.StringIO()
    w = csv.writer(s)
    w.writerow(["Rule", "Name", "Enabled", "Source", "Destination", "Service", "Action", "Hits", "Last Hit"])
    for r in data["rules"]:
        w.writerow([r["rule"], r["name"], r["enabled"], r["source"], r["destination"], r["service"], r["action"], r["hits"], r["last_hit"]])
    return StreamingResponse(iter([s.getvalue()]), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="{layer.replace(" ", "_")}_analysis.csv"'})
