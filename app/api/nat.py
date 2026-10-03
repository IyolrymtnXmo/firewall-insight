"""NAT rulebase analysis."""

from __future__ import annotations

from fastapi import APIRouter, Query, BackgroundTasks
import uuid

from ..policy import analyze_nat
from ..progress import progress_done, progress_set
from ..runtime import use_client

router = APIRouter()


@router.get("/api/nat-analyze")
async def nat_analyze(background_tasks: BackgroundTasks, package: str = Query(...), rid: str | None = Query(None)):
    rid = rid or f"auto-{uuid.uuid4().hex}"
    async def background_run():
        try:
            async def run(c):
                # NAT analysis doesn't currently do step progress inside, so we just wrap it
                progress_set(rid, 0, "Analyzing NAT rulebase", 1)
                result = await analyze_nat(c, package)
                progress_done(rid, "NAT analysis complete", result=result)
            await use_client(run)
        except Exception as e:
            progress_done(rid, "Error during NAT analysis", error=getattr(e, "detail", str(e)))

    background_tasks.add_task(background_run)
    return {"background": True, "rid": rid, "message": "NAT analysis started in background"}
