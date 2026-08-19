"""Connectivity, metadata and live progress endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Query

from ..progress import _progress
from ..runtime import cache_clear, cache_get, cache_set, use_client
from ..version import APP_VERSION

router = APIRouter()


@router.get("/health")
async def health():
    return {
        "status": "ok",
        "version": APP_VERSION,
        "phase": "4.0",
        "mode": "read-only",
        "persistent_api_session": True,
    }

@router.get("/api/checkpoint/test")
async def test_connection():
    async def run(c):
        x = await c.login()
        return {"connected": True, "api_server_version": x.get("api-server-version") or x.get("web-api-version"), "read_only": True}
    return await use_client(run)

@router.get("/api/bootstrap")
async def bootstrap(force: bool = Query(False)):
    if force:
        cache_clear()
    lc, pc = cache_get("layers"), cache_get("packages")
    if lc is not None and pc is not None:
        return {"layers": lc, "packages": pc, "cached": True}
    async def run(c):
        nonlocal lc, pc
        if lc is None:
            lc = await c.show_access_layers()
            cache_set("layers", lc)
        if pc is None:
            pc = await c.show_packages()
            cache_set("packages", pc)
        return {"layers": lc, "packages": pc, "cached": False}
    return await use_client(run)


@router.get("/api/progress")
async def get_progress(rid: str = Query(...)):
    """Polled by the UI while a long request runs. Never takes heavy_lock."""
    return _progress.get(rid) or {"phase": 0, "total": 0, "label": "", "done": False}
