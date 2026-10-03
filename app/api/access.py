"""Access Control policy: raw rulebase and optimizer analysis."""

from __future__ import annotations

from fastapi import APIRouter, Query, BackgroundTasks
import uuid

from ..policy import (access_tree, analyze_layer, analyze_package,
                      browse_package)
from ..policy_browser import browse_access_rulebase
from ..inline_layers import aggregate_browser
from ..progress import progress_done, progress_set
from ..runtime import cache_get, cache_pop, cache_set, use_client

router = APIRouter()


@router.get("/api/policy-browser")
async def policy_browser(background_tasks: BackgroundTasks, layer: str = Query(...), force: bool = Query(False), rid: str | None = Query(None)):
    key = f"policy-browser:{layer}"
    if force:
        cache_pop(key)

    cached = cache_get(key)
    if cached is not None:
        return cached

    rid = rid or f"auto-{uuid.uuid4().hex}"
    async def background_run():
        try:
            async def run(c):
                tree = await access_tree(c, layer, hydrate=False)
                browsed = [browse_access_rulebase(node["payload"]) for node in tree.get("layers", [])]
                result = aggregate_browser(tree, browsed)
                cache_set(key, result)
                progress_done(rid, "Browser load complete", result=result)
            await use_client(run)
        except Exception as e:
            progress_done(rid, "Error loading policy browser", error=getattr(e, "detail", str(e)))

    background_tasks.add_task(background_run)
    return {"background": True, "rid": rid, "message": "Loading browser in background"}


@router.get("/api/package-analyze")
async def package_analyze(background_tasks: BackgroundTasks, package: str = Query(...), rid: str | None = Query(None)):
    rid = rid or f"auto-{uuid.uuid4().hex}"
    async def background_run():
        try:
            async def run(c):
                result = await analyze_package(c, package, rid=rid)
                progress_done(rid, "Analysis complete", result=result)
            await use_client(run)
        except Exception as e:
            progress_done(rid, "Error during analysis", error=getattr(e, "detail", str(e)))

    background_tasks.add_task(background_run)
    return {"background": True, "rid": rid, "message": "Analysis started in background"}


@router.get("/api/package-policy-browser")
async def package_policy_browser(background_tasks: BackgroundTasks, package: str = Query(...), force: bool = Query(False), rid: str | None = Query(None)):
    if force:
        cache_pop(f"package-browser:{package}")
        cache_pop(f"package-access-tree:{package}:raw")
        
    rid = rid or f"auto-{uuid.uuid4().hex}"
    async def background_run():
        try:
            async def run(c):
                result = await browse_package(c, package)
                progress_done(rid, "Browser load complete", result=result)
            await use_client(run)
        except Exception as e:
            progress_done(rid, "Error loading package browser", error=getattr(e, "detail", str(e)))

    background_tasks.add_task(background_run)
    return {"background": True, "rid": rid, "message": "Loading package browser in background"}


@router.get("/api/package-context")
async def package_context(package: str = Query(...)):
    async def run(c):
        return {
            "package": package,
            "access_layers": await c.show_package_access_layers(package),
        }
    return await use_client(run)


@router.get("/api/analyze")
async def analyze(background_tasks: BackgroundTasks, layer: str = Query(...), rid: str | None = Query(None)):
    rid = rid or f"auto-{uuid.uuid4().hex}"
    async def background_run():
        try:
            async def run(c):
                result = await analyze_layer(c, layer)
                progress_done(rid, "Analysis complete", result=result)
            await use_client(run)
        except Exception as e:
            progress_done(rid, "Error during analysis", error=getattr(e, "detail", str(e)))

    background_tasks.add_task(background_run)
    return {"background": True, "rid": rid, "message": "Analysis started in background"}
