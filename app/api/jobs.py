"""
Review runs and the schedules that trigger them.

These are the second and third mutating routes in the application, after the
credential ones, and like those they write to local files only: a schedule
lives in `schedules.json` and a run in `runs/`. Nothing here sends anything to
a Management Server or a gateway except through `run_review()`, which issues
the same read-only `show-*` calls every page issues.

The listing routes exist to answer a specific question, and it is the question
somebody responsible for the firewall will ask first: *what is this thing doing
to my Management Server without me?* `GET /api/schedules` answers it - every
schedule, whether it is on, when it next fires, and how the last one ended.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any
import uuid

from fastapi import APIRouter, HTTPException, Query, Response, BackgroundTasks
from pydantic import BaseModel

from ..jobs import schedule as schedules
from ..jobs import store
from ..jobs.report import DETAIL_LEVELS, build_report
from ..jobs.runner import run_review
from ..progress import progress_done, progress_set
from ..runtime import use_client

router = APIRouter()

# One at a time. run_review() already serialises on heavy_lock inside the
# policy layer, but a second caller queueing behind it would still pay the
# whole Management API cost twice for the same answer.
_running = asyncio.Lock()


class ScheduleIn(BaseModel):
    id: str | None = None
    enabled: bool = False
    package: str
    profile: str | None = None
    at: str
    days: list[str] | None = None
    include_health: bool = True
    catch_up: bool = True
    pdf: bool = False
    pdf_detail: str = "summary"
    pdf_dir: str = "reports"


# ---- runs ------------------------------------------------------------------

@router.get("/api/runs")
async def list_runs():
    return {"runs": store.list_runs(), "directory": str(store.RUN_DIR)}


@router.get("/api/runs/{run_id}")
async def get_run(run_id: str):
    try:
        return store.load_run(run_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/api/runs/{run_id}/report.pdf")
async def get_run_report(run_id: str, detail: str = Query("summary")):
    """The PDF. `detail` decides how much of the policy it may contain."""
    if detail not in DETAIL_LEVELS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown detail level '{detail}'. Use one of: "
                   f"{', '.join(DETAIL_LEVELS)}.")
    try:
        run = store.load_run(run_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    pdf = build_report(run, detail)
    stamp = str(run.get("started_at", ""))[:10]
    name = f"firewall-review-{run.get('package', 'package')}-{stamp}-{detail}.pdf"
    return Response(
        content=pdf, media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{name}"'})


@router.post("/api/runs")
async def start_run(
    background_tasks: BackgroundTasks,
    package: str = Query(...),
    profile: str | None = Query(None),
    include_health: bool = Query(True),
    notify: bool = Query(False),
    rid: str | None = Query(None),
):
    rid = rid or f"auto-{uuid.uuid4().hex}"
    """Run a review now and return it. Same work the schedule does.

    `notify` sends it to the alert destinations whose triggers it meets, as a
    scheduled run would. Off by default: pressing a button to look at something
    is not usually a reason to message a channel.
    """
    if _running.locked():
        raise HTTPException(
            status_code=409,
            detail="A review is already running. Wait for it to finish - two at "
                   "once would read the same policy twice.")

    async def background_run():
        try:
            async def run(c):
                async with _running:
                    def on_step(i, total, label):
                        progress_set(rid, i, label, total)

                    result = await run_review(c, package, profile=profile,
                                              include_health=include_health,
                                              on_step=on_step)
                    result["triggered_by"] = {"kind": "manual"}
                    result["id"] = store.save_run(result)
                    if notify:
                        from ..jobs.alerts import dispatch
                        result["alerts"] = await dispatch(result)
                        store.save_run(result)
                    progress_done(rid, "Review complete", result=result)
            await use_client(run)
        except Exception as e:
            error_msg = getattr(e, "detail", str(e))
            progress_done(rid, "Error running review", error=error_msg)

    background_tasks.add_task(background_run)
    return {"background": True, "rid": rid, "message": "Manual review run started in background"}


# ---- schedules -------------------------------------------------------------

def _decorate(s: dict[str, Any], now: datetime) -> dict[str, Any]:
    nxt = schedules.next_due(s, now)
    return {**s, "next_due": nxt.isoformat(timespec="minutes") if nxt else None}


@router.get("/api/schedules")
async def list_schedules():
    now = datetime.now()
    rows = [_decorate(s, now) for s in schedules.load_all()]
    return {
        "schedules": rows,
        "any_enabled": any(s["enabled"] for s in rows),
        "file": str(schedules.SCHEDULE_FILE),
        "notes": [
            "A schedule is off when it is created. Enabling one is what makes "
            "this application read the Management Server without being asked.",
            "Times are this machine's local clock. Recorded times are UTC.",
            "The loop checks once a minute and runs one review at a time.",
        ],
    }


@router.put("/api/schedules")
async def save_schedule(entry: ScheduleIn):
    try:
        return _decorate(schedules.upsert(entry.model_dump()), datetime.now())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.delete("/api/schedules/{sid}")
async def delete_schedule(sid: str):
    if not schedules.remove(sid):
        raise HTTPException(status_code=404, detail=f"No schedule with id '{sid}'.")
    return {"status": "deleted", "id": sid}
