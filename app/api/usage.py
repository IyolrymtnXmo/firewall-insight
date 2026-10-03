"""Rule usage from the firewall logs, beside the hit counter."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, BackgroundTasks
import uuid

from .. import log_usage
from ..estate_reads import TIME_FRAMES, log_records
from ..policy import package_access_tree
from ..progress import progress_done, progress_set
from ..runtime import cache_get, cache_set, use_client
from ..snapshot import build_snapshot

router = APIRouter()


@router.get("/api/rule-usage")
async def rule_usage(background_tasks: BackgroundTasks,
                     package: str = Query(...),
                     time_frame: str = Query("last-7-days"),
                     # ~7 s per 100 records on the lab's log server, so the
                     # default is about a minute; raise it knowingly.
                     cap: int = Query(1000, ge=100, le=20000),
                     rid: str | None = Query(None)):
    rid = rid or f"auto-{uuid.uuid4().hex}"
    if time_frame not in TIME_FRAMES:
        raise HTTPException(400, f"time_frame must be one of {', '.join(TIME_FRAMES)}")
    key = f"rule-usage:{package}:{time_frame}:{cap}"
    cached = cache_get(key)
    if cached is not None:
        return cached

    async def background_run():
        try:
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
                progress_done(rid, "Rule usage complete", result=result)

            await use_client(run)
        except Exception as e:
            error_msg = getattr(e, "detail", str(e))
            progress_done(rid, "Error getting rule usage", error=error_msg)

    background_tasks.add_task(background_run)
    return {"background": True, "rid": rid, "message": "Rule usage started in background"}
