"""Access Control policy: raw rulebase and optimizer analysis."""

from __future__ import annotations

from fastapi import APIRouter, Query

from ..policy import (access_tree, analyze_layer, analyze_package,
                      browse_package, data_quality)
from ..policy_browser import browse_access_rulebase
from ..inline_layers import aggregate_browser
from ..runtime import cache_get, cache_pop, cache_set, use_client

router = APIRouter()


@router.get("/api/policy-browser")
async def policy_browser(layer: str = Query(...), force: bool = Query(False)):
    key = f"policy-browser:{layer}"
    if force:
        cache_pop(key)

    cached = cache_get(key)
    if cached is not None:
        return cached

    async def run(c):
        tree = await access_tree(c, layer, hydrate=False)
        browsed = [browse_access_rulebase(node["payload"]) for node in tree.get("layers", [])]
        result = aggregate_browser(tree, browsed)
        cache_set(key, result)
        return result

    return await use_client(run)


@router.get("/api/package-analyze")
async def package_analyze(package: str = Query(...), rid: str | None = Query(None)):
    return await use_client(lambda c: analyze_package(c, package, rid=rid))


@router.get("/api/package-policy-browser")
async def package_policy_browser(package: str = Query(...), force: bool = Query(False)):
    if force:
        cache_pop(f"package-browser:{package}")
        cache_pop(f"package-access-tree:{package}:raw")
    return await use_client(lambda c: browse_package(c, package))


@router.get("/api/package-context")
async def package_context(package: str = Query(...)):
    async def run(c):
        return {
            "package": package,
            "access_layers": await c.show_package_access_layers(package),
        }
    return await use_client(run)

@router.get("/api/analyze")
async def analyze(layer: str = Query(...)):
    return await use_client(lambda c: analyze_layer(c, layer))


@router.get("/api/analyze")
async def analyze(layer: str = Query(...)):
    return await use_client(lambda c: analyze_layer(c, layer))
