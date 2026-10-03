"""Object hygiene: unused, duplicated, and groups that could be written shorter."""

from __future__ import annotations

from fastapi import APIRouter, Query, BackgroundTasks
import uuid

from .. import object_hygiene as hygiene
from ..estate_reads import object_definitions, unused_objects, where_used
from ..progress import progress_done, progress_set
from ..runtime import cache_get, cache_pop, cache_set, use_client

router = APIRouter()


@router.get("/api/objects/hygiene")
async def objects_hygiene(background_tasks: BackgroundTasks,
                          cap: int = Query(2000, ge=50, le=20000),
                          force: bool = Query(False), rid: str | None = Query(None)):
    rid = rid or f"auto-{uuid.uuid4().hex}"
    key = f"object-hygiene:{cap}"
    if force:
        cache_pop(key)
    cached = cache_get(key)
    if cached is not None:
        return cached

    async def background_run():
        try:
            async def run(c):
                STEPS = 2
                progress_set(rid, 0, "Asking the Management Server which objects are unused", STEPS)
                unused, unused_total, unused_capped = await unused_objects(c, cap)
                progress_set(rid, 1, "Reading hosts, networks, ranges and groups", STEPS)
                defs = await object_definitions(c, cap)
                result = {
                    "unused": {**hygiene.unused_summary(unused), "total": unused_total,
                               "capped": unused_capped},
                    "duplicates": hygiene.duplicates(defs),
                    "merges": hygiene.merge_suggestions(defs),
                    "scanned": {k: {"read": len(v["objects"]), "total": v["total"],
                                    "capped": v["capped"]} for k, v in defs.items()},
                    "notes": list(hygiene.NOTES),
                }
                if any(v["capped"] for v in defs.values()):
                    result["notes"].append(
                        "At least one object type has more objects than were read, so duplicates "
                        "and merges are among the objects read, not across the whole domain.")
                cache_set(key, result)
                progress_done(rid, "Object hygiene complete", result=result)

            await use_client(run)
        except Exception as e:
            error_msg = getattr(e, "detail", str(e))
            progress_done(rid, "Error during object hygiene", error=error_msg)

    background_tasks.add_task(background_run)
    return {"background": True, "rid": rid, "message": "Object hygiene started in background"}


@router.get("/api/objects/where-used")
async def objects_where_used(uid: str = Query(...)):
    async def run(c):
        raw = await where_used(c, uid)
        direct = raw.get("used-directly") or {}
        return {
            "uid": uid,
            "total": direct.get("total", 0),
            "access_rules": [{"rule": (r.get("rule") or {}).get("name") or r.get("position"),
                              "layer": (r.get("layer") or {}).get("name"),
                              "package": (r.get("package") or {}).get("name"),
                              "columns": r.get("rule-columns") or []}
                             for r in direct.get("access-control-rules") or []],
            "nat_rules": len(direct.get("nat-rules") or []),
            "objects": [o.get("name") for o in direct.get("objects") or []],
            "threat_prevention_rules": len(direct.get("threat-prevention-rules") or []),
        }
    return await use_client(run)
