"""Gateway and server topology."""

from __future__ import annotations

from fastapi import APIRouter, Query

from ..runtime import cache_get, cache_pop, cache_set, heavy_lock, use_client
from ..traffic import network_map

router = APIRouter()


@router.get("/api/network-map")
async def get_network_map(force: bool = Query(False)):
    if force:
        cache_pop("network-map")
    cached = cache_get("network-map")
    if cached is not None:
        return cached
    async def run(c):
        async with heavy_lock:
            objs = await c.show_gateways_and_servers()
            result = network_map(objs)
            cache_set("network-map", result)
            return result
    return await use_client(run)
