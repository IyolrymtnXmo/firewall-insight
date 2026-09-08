"""Gateway and server topology, and the optional routing overlay.

Routing is opt-in twice over: the caller has to ask for it, and GAIA_ENABLED
has to be true. Asking for it while it is off is answered with a reason rather
than a quietly identical map - "I did not draw routes" and "there are no
routes" must not look the same.
"""

from __future__ import annotations

from fastapi import APIRouter, Query

from ..config import settings
from ..gaia import read_all_routes
from ..gaia_topology import add_routing
from ..runtime import cache_get, cache_pop, cache_set, heavy_lock, use_client
from ..traffic import network_map

router = APIRouter()


@router.get("/api/network-map")
async def get_network_map(
    force: bool = Query(False),
    routing: bool = Query(False, description="overlay routing read from the Gaia API"),
):
    if force:
        cache_pop("network-map")
        cache_pop("network-map:routed")
    key = "network-map:routed" if routing else "network-map"
    cached = cache_get(key)
    if cached is not None:
        return cached

    async def run(c):
        async with heavy_lock:
            base = cache_get("network-map")
            if base is None:
                base = network_map(await c.show_gateways_and_servers())
                cache_set("network-map", base)
            if not routing:
                return base

            if not settings.gaia_enabled:
                result = {**base, "limitations": base["limitations"] + [
                    "Routing was requested but GAIA_ENABLED is false, so no route "
                    "was read and none is drawn. This map shows configured "
                    "interfaces only - it is not evidence that the gateways have "
                    "no routes."],
                    "routing": {"enabled": False}}
                return result

            result = add_routing(base, await read_all_routes())
            result.setdefault("routing", {})["enabled"] = True
            cache_set(key, result)
            return result

    return await use_client(run)
