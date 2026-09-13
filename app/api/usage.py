"""Rule usage from the firewall logs, beside the hit counter."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from .. import log_usage
from ..estate_reads import TIME_FRAMES, log_records
from ..policy import package_access_tree
from ..progress import progress_done, progress_set
from ..runtime import cache_get, cache_set, use_client
from ..snapshot import build_snapshot

router = APIRouter()


@router.get("/api/rule-usage")
async def rule_usage(package: str = Query(...),
                     time_frame: str = Query("last-7-days"),
                     cap: int = Query(3000, ge=100, le=50000),
                     rid: str | None = Query(None)):
    if time_frame not in TIME_FRAMES:
        raise HTTPException(400, f"time_frame must be one of {', '.join(TIME_FRAMES)}")
    key = f"rule-usage:{package}:{time_frame}:{cap}"
    cached = cache_get(key)
    if cached is not None:
        progress_done(rid, "Served from cache")
        return cached

    async def run(c):
        STEPS = 3
        progress_set(rid, 0, "Loading the package's rules", STEPS)
        tree = await package_access_tree(c, package, hydrate=True)
        rules = build_snapshot(tree, None, package)["access"]["rules"]
        progress_set(rid, 1, f"Reading up to {cap:,} firewall log records ({time_frame})", STEPS)
        records, capped = await log_records(c, time_frame, cap)
        progress_set(rid, 2, "Counting records per rule", STEPS)
        result = log_usage.usage(rules, log_usage.aggregate(records, package),
                                 capped=capped, time_frame=time_frame)
        result["package"] = package
        cache_set(key, result)
        progress_done(rid, "Rule usage complete")
        return result

    return await use_client(run)
