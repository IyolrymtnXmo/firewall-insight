"""
Policy orchestration: fetch, hydrate, analyse, cache.

This is the layer between the raw Management API client and the HTTP routes.
It owns the two things that make Check Point policy hard - the Inline Layer
tree and object hydration - plus the per-result honesty report.
"""

from __future__ import annotations

from .analyzer import analyze_rulebase, collect_referenced_uids
from .checkpoint import CheckPointAPIError
from .inline_layers import aggregate_analyses, aggregate_browser, merge_package_trees
from .nat_analyzer import analyze_nat_rulebase
from .policy_browser import browse_access_rulebase
from .progress import _progress, progress_done, progress_set
from .runtime import cache_get, cache_set, heavy_lock

MAX_HYDRATION_ROUNDS = 6


async def hydrate_rulebase(c, data, on_progress=None):
    """
    Resolve every object a rule references down to comparable ranges.

    Two things make this more than a single pass:

    1. objects-dictionary entries from details-level=standard are thin -
       groups have no members, gateways have no address - so an entry being
       present is not the same as it being usable. `needs_detail()` decides.
    2. Groups nest, so each round can reveal members that themselves need
       fetching.
    """
    from .resolver import needs_detail

    existing = {o["uid"]: o for o in data.get("objects-dictionary", []) if isinstance(o, dict) and o.get("uid")}
    need = collect_referenced_uids(data)

    for round_no in range(MAX_HYDRATION_ROUNDS):
        existing = await c.hydrate_objects(
            need, existing,
            on_progress=(lambda i, n, r=round_no: on_progress(i, n, r)) if on_progress else None,
        )
        discovered = set()
        for o in existing.values():
            for key in ("members", "include", "except"):
                v = o.get(key)
                if isinstance(v, list):
                    for x in v:
                        uid = x if isinstance(x, str) else x.get("uid") if isinstance(x, dict) else None
                        if uid:
                            discovered.add(uid)
                elif isinstance(v, dict) and v.get("uid"):
                    discovered.add(v["uid"])
        # A nested member can already be in the dictionary yet still be a thin
        # standard-level stub, so re-check completeness, not just presence.
        new = {
            uid for uid in discovered
            if uid not in existing or needs_detail(existing[uid])
        }
        if not new:
            break
        need = new

    data["objects-dictionary"] = list(existing.values())
    return data, existing


def data_quality(c, tree) -> dict:
    """
    Report how trustworthy this result is, so the UI can say so out loud.

    A partially-loaded policy must never be presented as a complete one. The
    UI turns these into a visible banner rather than leaving the gap for the
    user to discover from a wrong number.
    """
    errors = tree.get("errors", []) or []
    truncated = bool(getattr(c, "hydration_truncated", False))
    return {
        "complete": not errors and not truncated,
        "failed_inline_layers": len(errors),
        "inline_layer_errors": errors[:10],
        "object_hydration_truncated": truncated,
        "warnings": (
            ([f"{len(errors)} Inline Layer(s) could not be loaded; "
              "rules inside them were not analyzed."] if errors else [])
            + (["Object detail loading stopped early on Management API rate "
                "limiting. Some objects may be unresolved, which can turn "
                "matches into Unknown. Retry, or raise "
                "CHECKPOINT_MIN_REQUEST_INTERVAL."] if truncated else [])
        ),
    }


async def access_tree(c, layer, hydrate: bool = True):
    key = f"access-tree:{layer}:{'hydrated' if hydrate else 'raw'}"
    cached = cache_get(key)
    if cached is not None:
        return cached

    # Reuse hydrated tree for raw browsing when available.
    if not hydrate:
        hydrated = cache_get(f"access-tree:{layer}:hydrated")
        if hydrated is not None:
            return hydrated

    async with heavy_lock:
        tree = await c.show_rulebase_tree(layer)
        if hydrate:
            for node in tree.get("layers", []):
                payload, _ = await hydrate_rulebase(c, node["payload"])
                node["payload"] = payload

        cache_set(key, tree)
        if hydrate:
            cache_set(f"access-tree:{layer}:raw", tree)
        return tree


async def package_access_tree(c, package: str, hydrate: bool = True, rid: str | None = None):
    key = f"package-access-tree:{package}:{'hydrated' if hydrate else 'raw'}"
    cached = cache_get(key)
    if cached is not None:
        return cached

    roots = await c.show_package_access_layers(package)
    if not roots:
        raise CheckPointAPIError(
            f"Could not resolve an Access Control layer for Policy Package '{package}'."
        )

    trees = []
    for root in roots:
        trees.append(await c.show_rulebase_tree(root["name"]))

    tree = merge_package_trees(package, trees)

    if hydrate:
        layers = tree.get("layers", [])
        for i, node in enumerate(layers, 1):
            # Object hydration dominates first-load time. Report per-object
            # movement so a 20s wait shows real progress, not a frozen step.
            def report(done, total, round_no, _i=i, _name=node.get("name")):
                if not rid:
                    return
                item = _progress.get(rid) or {}
                suffix = f" · pass {round_no + 1}" if round_no else ""
                progress_set(
                    rid, item.get("phase", 0), item.get("label", "Loading"),
                    item.get("total", 0),
                    f"{_name}: resolving object {done}/{total}"
                    f"{f' (layer {_i}/{len(layers)})' if len(layers) > 1 else ''}{suffix}",
                )

            payload, _ = await hydrate_rulebase(
                c, node["payload"], on_progress=report if rid else None
            )
            node["payload"] = payload

    cache_set(key, tree)
    if hydrate:
        cache_set(f"package-access-tree:{package}:raw", tree)
    return tree


async def analyze_package(c, package: str, rid: str | None = None):
    key = f"package-analysis:{package}"
    cached = cache_get(key)
    if cached is not None:
        progress_done(rid, "Served from cache")
        return cached

    STEPS = 3
    progress_set(rid, 0, "Loading package and inline layers", STEPS)
    tree = await package_access_tree(c, package, hydrate=True, rid=rid)
    progress_set(rid, 1, "Analyzing each layer", STEPS)
    from .inline_layers import annotate_analysis
    analyses = [
        annotate_analysis(analyze_rulebase(node["payload"]), node)
        for node in tree.get("layers", [])
    ]
    progress_set(rid, 2, "Aggregating findings", STEPS)
    result = aggregate_analyses(tree, analyses)
    result["package"] = package
    result["root_layers"] = tree.get("root_layers", [])
    result["data_quality"] = data_quality(c, tree)
    cache_set(key, result)
    progress_done(rid, "Analysis complete")
    return result


async def browse_package(c, package: str):
    key = f"package-browser:{package}"
    cached = cache_get(key)
    if cached is not None:
        return cached

    tree = await package_access_tree(c, package, hydrate=False)
    browsed = [
        browse_access_rulebase(node["payload"])
        for node in tree.get("layers", [])
    ]
    result = aggregate_browser(tree, browsed)
    result["package"] = package
    result["root_layers"] = tree.get("root_layers", [])
    result["data_quality"] = data_quality(c, tree)
    cache_set(key, result)
    return result

async def analyze_layer(c, layer):
    key = f"analysis:{layer}"
    cached = cache_get(key)
    if cached is not None:
        return cached

    tree = await access_tree(c, layer, hydrate=True)
    analyses = []
    for node in tree.get("layers", []):
        result = analyze_rulebase(node["payload"])
        from .inline_layers import annotate_analysis
        analyses.append(annotate_analysis(result, node))

    result = aggregate_analyses(tree, analyses)
    cache_set(key, result)
    return result

async def analyze_nat(c, package):
    key = f"nat-analysis:{package}"
    cached = cache_get(key)
    if cached is not None:
        return cached
    async with heavy_lock:
        data = await c.show_nat_rulebase(package)
        result = analyze_nat_rulebase(data)
        cache_set(key, result)
        cache_set(f"nat:{package}", data)
        return result
