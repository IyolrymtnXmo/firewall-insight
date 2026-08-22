"""CSV exports of the raw policy and of the analysis."""

from __future__ import annotations

import csv
import io

from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse

from ..inline_layers import aggregate_browser
from ..policy import access_tree, analyze_layer, browse_package
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


RAW_COLUMNS = [
    "Layer", "Layer Path", "Parent Rule", "Rule", "Display Rule", "Section",
    "Name", "Enabled", "Source", "Destination", "VPN", "Service", "Action",
    "Track", "Install On", "Time", "Inline Layer", "Comments", "Hits", "Last Hit",
]


@router.get("/api/package-policy-browser.csv")
async def package_policy_browser_csv(package: str = Query(...)):
    """
    Export the whole package, inline layers included.

    The UI became package-first in v4.2 but this export stayed layer-first, so
    the Access Policy page's Export button had nothing to call and printed a
    "will be added later" message instead. Display Rule is included so an
    inline row reads 7.1 rather than an ambiguous 1.
    """
    data = await use_client(lambda c: browse_package(c, package))

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(RAW_COLUMNS)
    for r in data.get("rules", []):
        writer.writerow([
            r.get("layer"), r.get("layer_path"), r.get("parent_rule"),
            r.get("rule"), r.get("display_rule"), r.get("section"), r.get("name"),
            r.get("enabled"), r.get("source"), r.get("destination"), r.get("vpn"),
            r.get("service"), r.get("action"), r.get("track"), r.get("install_on"),
            r.get("time"), r.get("inline_layer"), r.get("comments"),
            r.get("hits"), r.get("last_hit"),
        ])

    safe = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in package)
    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{safe}_raw_policy.csv"'},
    )