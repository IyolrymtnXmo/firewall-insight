from __future__ import annotations

import asyncio
import csv
import io
import time

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, StreamingResponse

from .checkpoint import CheckPointClient, CheckPointAPIError, CheckPointRateLimitError
from .analyzer import analyze_rulebase, collect_referenced_uids
from .nat_analyzer import analyze_nat_rulebase
from .policy_browser import browse_access_rulebase
from .inline_layers import aggregate_analyses, aggregate_browser, merge_package_trees
from .traffic import trace_access, trace_access_tree, correlate_nat, network_map, resolve_service_query
from .config import settings

APP_VERSION = "4.11.0"

app = FastAPI(
    title="Firewall Insight - Check Point Firewall Analysis Platform",
    version=APP_VERSION,
)

_cp = CheckPointClient()
_heavy_lock = asyncio.Lock()
_cache = {}

def cache_get(key):
    item = _cache.get(key)
    if not item:
        return None
    created, value = item
    if time.time() - created > settings.checkpoint_cache_ttl:
        _cache.pop(key, None)
        return None
    return value

def cache_set(key, value):
    _cache[key] = (time.time(), value)

def cache_clear():
    _cache.clear()

async def use_client(fn):
    try:
        return await fn(_cp)
    except CheckPointRateLimitError as e:
        raise HTTPException(status_code=429, detail=f"{e}. Rate limit retry/backoff was exhausted; wait briefly and retry.")
    except CheckPointAPIError as e:
        raise HTTPException(status_code=502, detail=str(e))

@app.on_event("shutdown")
async def shutdown_event():
    await _cp.close()

MAX_HYDRATION_ROUNDS = 6


async def hydrate_rulebase(c, data):
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

    for _ in range(MAX_HYDRATION_ROUNDS):
        existing = await c.hydrate_objects(need, existing)
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

    async with _heavy_lock:
        tree = await c.show_rulebase_tree(layer)
        if hydrate:
            for node in tree.get("layers", []):
                payload, _ = await hydrate_rulebase(c, node["payload"])
                node["payload"] = payload

        cache_set(key, tree)
        if hydrate:
            cache_set(f"access-tree:{layer}:raw", tree)
        return tree


async def package_access_tree(c, package: str, hydrate: bool = True):
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
        for node in tree.get("layers", []):
            payload, _ = await hydrate_rulebase(c, node["payload"])
            node["payload"] = payload

    cache_set(key, tree)
    if hydrate:
        cache_set(f"package-access-tree:{package}:raw", tree)
    return tree


async def analyze_package(c, package: str):
    key = f"package-analysis:{package}"
    cached = cache_get(key)
    if cached is not None:
        return cached

    tree = await package_access_tree(c, package, hydrate=True)
    from .inline_layers import annotate_analysis
    analyses = [
        annotate_analysis(analyze_rulebase(node["payload"]), node)
        for node in tree.get("layers", [])
    ]
    result = aggregate_analyses(tree, analyses)
    result["package"] = package
    result["root_layers"] = tree.get("root_layers", [])
    result["data_quality"] = data_quality(c, tree)
    cache_set(key, result)
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
    async with _heavy_lock:
        data = await c.show_nat_rulebase(package)
        result = analyze_nat_rulebase(data)
        cache_set(key, result)
        cache_set(f"nat:{package}", data)
        return result

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "version": APP_VERSION,
        "phase": "4.0",
        "mode": "read-only",
        "persistent_api_session": True,
    }

@app.get("/api/checkpoint/test")
async def test_connection():
    async def run(c):
        x = await c.login()
        return {"connected": True, "api_server_version": x.get("api-server-version") or x.get("web-api-version"), "read_only": True}
    return await use_client(run)

@app.get("/api/bootstrap")
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


@app.get("/api/policy-browser")
async def policy_browser(layer: str = Query(...), force: bool = Query(False)):
    key = f"policy-browser:{layer}"
    if force:
        _cache.pop(key, None)

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


@app.get("/api/package-analyze")
async def package_analyze(package: str = Query(...)):
    return await use_client(lambda c: analyze_package(c, package))


@app.get("/api/package-policy-browser")
async def package_policy_browser(package: str = Query(...), force: bool = Query(False)):
    if force:
        _cache.pop(f"package-browser:{package}", None)
        _cache.pop(f"package-access-tree:{package}:raw", None)
    return await use_client(lambda c: browse_package(c, package))


@app.get("/api/package-context")
async def package_context(package: str = Query(...)):
    async def run(c):
        return {
            "package": package,
            "access_layers": await c.show_package_access_layers(package),
        }
    return await use_client(run)

@app.get("/api/analyze")
async def analyze(layer: str = Query(...)):
    return await use_client(lambda c: analyze_layer(c, layer))

@app.get("/api/nat-analyze")
async def nat_analyze(package: str = Query(...)):
    return await use_client(lambda c: analyze_nat(c, package))


@app.get("/api/policy-browser.csv")
async def policy_browser_csv(layer: str = Query(...)):
    data = await use_client(
        lambda c: _policy_browser_for_export(c, layer)
    )
    s = io.StringIO()
    w = csv.writer(s)
    w.writerow([
        "Layer", "Layer Path", "Parent Rule", "Rule", "Section", "Name", "Enabled", "Source", "Destination",
        "VPN", "Service", "Action", "Track", "Install On", "Time",
        "Inline Layer", "Comments", "Hits", "Last Hit"
    ])
    for r in data["rules"]:
        w.writerow([
            r.get("layer"), r.get("layer_path"), r.get("parent_rule"), r["rule"], r["section"], r["name"], r["enabled"], r["source"],
            r["destination"], r["vpn"], r["service"], r["action"], r["track"],
            r["install_on"], r["time"], r["inline_layer"], r["comments"],
            r["hits"], r["last_hit"]
        ])
    return StreamingResponse(
        iter([s.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition":
                f'attachment; filename="{layer.replace(" ", "_")}_raw_policy.csv"'
        },
    )

async def _policy_browser_for_export(c, layer):
    key = f"policy-browser:{layer}"
    cached = cache_get(key)
    if cached is not None:
        return cached
    tree = await access_tree(c, layer, hydrate=False)
    browsed = [browse_access_rulebase(node["payload"]) for node in tree.get("layers", [])]
    result = aggregate_browser(tree, browsed)
    cache_set(key, result)
    return result

@app.get("/api/export.csv")
async def export_csv(layer: str = Query(...)):
    data = await use_client(lambda c: analyze_layer(c, layer))
    s = io.StringIO()
    w = csv.writer(s)
    w.writerow(["Rule", "Name", "Enabled", "Source", "Destination", "Service", "Action", "Hits", "Last Hit"])
    for r in data["rules"]:
        w.writerow([r["rule"], r["name"], r["enabled"], r["source"], r["destination"], r["service"], r["action"], r["hits"], r["last_hit"]])
    return StreamingResponse(iter([s.getvalue()]), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="{layer.replace(" ", "_")}_analysis.csv"'})

@app.get("/api/network-map")
async def get_network_map(force: bool = Query(False)):
    if force:
        _cache.pop("network-map", None)
    cached = cache_get("network-map")
    if cached is not None:
        return cached
    async def run(c):
        async with _heavy_lock:
            objs = await c.show_gateways_and_servers()
            result = network_map(objs)
            cache_set("network-map", result)
            return result
    return await use_client(run)

@app.get("/api/traffic-path")
async def traffic_path(
    layer: str = Query(...),
    src: str = Query(...),
    dst: str = Query(...),
    protocol: str = Query("tcp"),
    service: str | None = Query(None),
    port: int | None = Query(None, ge=0, le=65535),
    package: str | None = Query(None),
):
    async def run(c):
        service_input = str(
            service if service not in (None, "")
            else port if port is not None
            else ""
        ).strip()
        if not service_input:
            raise HTTPException(status_code=400, detail="Enter a Port or Service name.")

        # Load the complete package tree when a Policy Package is selected.
        # This is required to follow Parent Rule -> Inline Layer -> child rule.
        if package:
            tree = await package_access_tree(c, package, hydrate=True)
        else:
            tree = await access_tree(c, layer, hydrate=True)

        # Build a global resolver from all layer dictionaries so custom
        # service objects can be resolved regardless of which layer uses them.
        from .resolver import ObjectResolver
        objects = {}
        for node in tree.get("layers", []):
            for obj in node.get("payload", {}).get("objects-dictionary", []) or []:
                if isinstance(obj, dict) and obj.get("uid"):
                    objects[obj["uid"]] = obj
        resolver = ObjectResolver(objects)

        try:
            service_query = resolve_service_query(service_input, protocol, resolver)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

        access = trace_access_tree(
            tree,
            src,
            dst,
            protocol,
            service_query,
            selected_root=layer,
        )

        nat, nat_error = [], None
        if package:
            try:
                nd = cache_get(f"nat:{package}")
                if nd is None:
                    nd = await c.show_nat_rulebase(package)
                    cache_set(f"nat:{package}", nd)
                nat = correlate_nat(nd, src, dst, objects)
            except Exception as e:
                nat_error = str(e)

        return {
            "query": {
                "source": src,
                "destination": dst,
                "protocol": service_query.get("protocol", protocol.lower()),
                "port": service_query.get("port"),
                "service_input": service_input,
                "service_display": service_query.get("display"),
                "service_resolved_by": service_query.get("resolved_by"),
                "layer": layer,
                "package": package,
            },
            "access": access,
            "nat": nat,
            "nat_error": nat_error,
            "data_quality": data_quality(c, tree),
            "limitations": [
                "This is a configuration-based Access Control simulation.",
                "The trace now follows configured Inline Layers and Access Sections.",
                "Identity Awareness, dynamic objects, time objects, implied rules, live gateway state, routing and kernel behavior can still make a live log differ.",
                "NAT correlation is configuration-based and does not emulate the live routing/kernel path."
            ]
        }
    return await use_client(run)


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    return r"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Firewall Analysis Platform</title>
<style>
:root{
  font-family:Inter,Segoe UI,Arial,sans-serif;
  --bg:#0e0d13;--sidebar:#15131b;--panel:#17151e;--panel2:#1d1a25;--card:#1b1822;
  --line:#342d42;--text:#f6f2ff;--muted:#a79db8;--purple:#8b5cf6;--purple2:#a78bfa;
  --good:#38d996;--warn:#f6c453;--bad:#ff7184;--input:#111017;--shadow:0 16px 40px rgba(0,0,0,.30);
}
body.light{
  --bg:#f5f3fb;--sidebar:#ffffff;--panel:#ffffff;--panel2:#faf8ff;--card:#ffffff;
  --line:#ded8ec;--text:#1a1720;--muted:#71697f;--purple:#7c3aed;--purple2:#8b5cf6;
  --input:#ffffff;--shadow:0 12px 30px rgba(82,59,116,.10);
}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);min-height:100vh}
.app{display:grid;grid-template-columns:250px 1fr;min-height:100vh}
.sidebar{background:var(--sidebar);border-right:1px solid var(--line);padding:24px 18px;position:sticky;top:0;height:100vh;display:flex;flex-direction:column}
.brand{font-size:21px;font-weight:850;margin:2px 8px 26px}.brand span{color:var(--purple2)}
.menu{display:flex;flex-direction:column;gap:7px}.menu button{justify-content:flex-start;width:100%;text-align:left;border:none;background:transparent;color:var(--muted)}
.menu button.active{background:linear-gradient(90deg,var(--purple),#6d4bea);color:white}
.sidebar-bottom{margin-top:auto;border-top:1px solid var(--line);padding-top:16px}.theme-row{display:flex;align-items:center;justify-content:space-between;color:var(--muted);padding:9px}
.switch{width:48px;height:26px;border-radius:999px;background:#393247;position:relative;cursor:pointer}.switch i{position:absolute;width:20px;height:20px;border-radius:50%;background:white;top:3px;left:3px;transition:.2s}.light .switch i{left:25px}.light .switch{background:var(--purple)}
.main{padding:28px 34px;min-width:0}.header{display:flex;justify-content:space-between;align-items:flex-start;gap:18px}.header h1{margin:0;font-size:30px}.header p{margin:6px 0 0;color:var(--muted)}
.badge{padding:9px 13px;border-radius:999px;background:#183629;color:#72e7b2;border:1px solid #285443;font-size:13px}
.panel,.card{background:var(--panel);border:1px solid var(--line);border-radius:15px;box-shadow:var(--shadow)}
.panel{padding:20px;margin-top:18px}.controls{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
button,select,input{height:43px;border:1px solid var(--line);border-radius:9px;background:var(--input);color:var(--text);padding:0 14px;font-size:14px}
button{font-weight:700;cursor:pointer;display:inline-flex;align-items:center;justify-content:center}
button:hover{border-color:var(--purple2)}.primary{background:var(--purple);border-color:var(--purple);color:white}.primary:hover{background:#7c4ce4}
select{min-width:300px}.status{margin-top:13px;background:var(--input);border:1px solid var(--line);border-radius:10px;padding:13px 15px;color:#d8d0e5;white-space:pre-wrap}.light .status{color:#544c63}
.page{display:none}.page.active{display:block}.cards{display:grid;grid-template-columns:repeat(5,1fr);gap:13px;margin-top:18px}.card{padding:17px}.metric-label{color:var(--muted);font-size:13px}.metric{font-size:31px;font-weight:850;margin-top:7px}
.tabs{display:flex;gap:8px;flex-wrap:wrap;margin:18px 0 13px}.tabs button.active{background:var(--purple);border-color:var(--purple);color:white}
.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:12px;background:var(--panel2)}
table{width:100%;border-collapse:separate;border-spacing:0;font-size:13px;min-width:980px}th,td{padding:12px 13px;text-align:left;vertical-align:top;border-bottom:1px solid var(--line)}
th{background:rgba(139,92,246,.10);color:#d9cdf6;text-transform:uppercase;font-size:11px;letter-spacing:.05em;position:sticky;top:0}.light th{color:#54406f}
tbody tr:nth-child(even){background:rgba(255,255,255,.015)}tbody tr:hover{background:rgba(139,92,246,.08)}
.rule-no{font-weight:850;color:#d8c6ff}.light .rule-no{color:#6d28d9}.muted{color:var(--muted)}
.pill{display:inline-block;padding:4px 9px;border-radius:999px;font-size:11px;font-weight:800}.pill.warn{background:#4a3509;color:#ffd66d}.pill.good{background:#123a28;color:#7ce8b7}.pill.bad{background:#461824;color:#ff9aa7}.pill.purple{background:#33215e;color:#ccb6ff}.pill.inline{background:#17324a;color:#9fd2ff;border:1px solid #285675}
.section-title{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-top:20px}.section-title h2,.section-title h3{margin:0}
.flow{display:flex;gap:9px;align-items:stretch;flex-wrap:wrap;margin-top:16px}.step{flex:1;min-width:190px;background:var(--panel2);border:1px solid var(--line);border-radius:12px;padding:15px}.arrow{align-self:center;color:var(--purple2);font-size:23px}
.map{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}.node{border:1px solid var(--line);border-radius:12px;background:var(--panel2);padding:14px}
.topology{height:590px;border:1px solid var(--line);border-radius:14px;background:radial-gradient(circle at 50% 20%,rgba(139,92,246,.13),transparent 55%),var(--input);overflow:hidden}
.topology svg{width:100%;height:100%;cursor:grab}.topology svg:active{cursor:grabbing}.edge{stroke:#8061c6;stroke-width:2;fill:none}.edge-label{fill:var(--muted);font-size:11px}
.toponode rect{stroke-width:1.5}.toponode text{fill:var(--text);font-weight:750;font-size:12px}.toponode .sub{fill:var(--muted);font-size:10px;font-weight:400}
.gateway rect{fill:#281c49;stroke:#9b7cf8}.management rect{fill:#15382c;stroke:#46d89a}.interface rect{fill:#342341;stroke:#cf83ff}.network rect{fill:#45370f;stroke:#f2bd4e}.device rect{fill:#23202d;stroke:#7d748d}
.light .gateway rect{fill:#efe9ff}.light .management rect{fill:#e7f8ef}.light .interface rect{fill:#f5eaff}.light .network rect{fill:#fff6da}.light .device rect{fill:#f4f1f8}




.inline-parent-row{
  background:rgba(255,255,255,.018)!important;
  box-shadow:inset 3px 0 0 rgba(56,217,150,.50);
}
.inline-parent-row:hover{background:rgba(56,217,150,.045)!important}
.inline-child-row:hover{background:rgba(96,165,250,.10)!important}
.inline-child-row .rule-no{color:#b9dcff}
.inline-parent-row .rule-no{color:#d8c6ff}

.inline-parent-row td{
  border-bottom-color:rgba(139,92,246,.34)!important;
}
.inline-child-row{
  background:rgba(50,72,92,.12);
  box-shadow:inset 3px 0 0 rgba(96,165,250,.65);
}
.inline-child-row td:first-child{
  position:relative;
  padding-left:31px!important;
}
.inline-child-row td:first-child:before{
  content:"";
  position:absolute;
  left:13px;
  top:0;
  bottom:50%;
  width:1px;
  background:rgba(96,165,250,.58);
}
.inline-child-row td:first-child:after{
  content:"";
  position:absolute;
  left:13px;
  top:50%;
  width:12px;
  height:1px;
  background:rgba(96,165,250,.58);
}
.inline-layer-name{
  display:inline-flex;
  align-items:center;
  gap:5px;
}
.inline-layer-name:before{
  content:"↳";
  color:#93c5fd;
  font-weight:900;
}
.inline-findings-card{
  margin-top:14px;
  padding:14px 16px;
  border:1px solid rgba(244,197,66,.26);
  background:rgba(244,197,66,.055);
  border-radius:14px;
}
.inline-findings-grid{
  display:grid;
  grid-template-columns:repeat(5,minmax(0,1fr));
  gap:10px;
  margin-top:10px;
}
.inline-mini{
  border:1px solid var(--line);
  border-radius:11px;
  padding:10px 12px;
  min-width:0;
}
.inline-mini .v{font-size:20px;font-weight:800;margin-top:4px}
@media(max-width:1100px){.inline-findings-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}

.access-summary-grid{
  grid-template-columns:repeat(4,minmax(0,1fr))!important;
  width:100%;
}
.access-summary-grid .card{
  min-width:0;
  width:100%;
}
@media(max-width:1100px){
  .access-summary-grid{grid-template-columns:repeat(2,minmax(0,1fr))!important}
}
@media(max-width:650px){
  .access-summary-grid{grid-template-columns:1fr!important}
}


.alert-count{
  display:inline-flex;
  align-items:center;
  justify-content:center;
  min-width:38px;
  height:38px;
  padding:0 10px;
  border-radius:999px;
  background:#f4c542;
  color:#17120a;
  border:1px solid #ffd96a;
  box-shadow:0 0 0 3px rgba(244,197,66,.10);
  font-weight:800;
  line-height:1;
}
.metric .alert-count{
  font-size:.72em;
  vertical-align:middle;
}

.drill-card{cursor:pointer;transition:transform .15s ease,border-color .15s ease,box-shadow .15s ease}
.drill-card:hover{transform:translateY(-2px);border-color:var(--purple2);box-shadow:0 14px 34px rgba(124,58,237,.18)}
.drill-row{cursor:pointer}
.drill-row:hover td{background:rgba(124,58,237,.10)}
.alert-count{cursor:pointer}
.hidden{display:none}.hint{font-size:12px;color:var(--muted)}
@media(max-width:1100px){.dashboard-grid{grid-template-columns:1fr!important}.app{grid-template-columns:1fr}.sidebar{position:relative;height:auto}.menu{flex-direction:row;overflow:auto}.sidebar-bottom{display:none}.cards{grid-template-columns:repeat(2,1fr)}.main{padding:20px}}

/* ============================================================
   v4.11 UX layer: progress, blur overlay, toasts, skeletons,
   empty/error states, responsive shell, motion.
   ============================================================ */

:root{
  --ease:cubic-bezier(.22,.61,.36,1);
  --ease-out:cubic-bezier(.16,1,.3,1);
  --t-fast:140ms;
  --t:220ms;
  --t-slow:380ms;
  --glass:rgba(14,13,19,.62);
  --radius:14px;
}
.light{
  --glass:rgba(255,255,255,.62);
}

*,*::before,*::after{box-sizing:border-box}

/* Respect the OS setting. Motion is decoration, never the only signal. */
@media(prefers-reduced-motion:reduce){
  *,*::before,*::after{
    animation-duration:.001ms!important;
    animation-iteration-count:1!important;
    transition-duration:.001ms!important;
    scroll-behavior:auto!important;
  }
}

/* ---------- 1. Top progress bar (global request activity) ---------- */
#topProgress{
  position:fixed;top:0;left:0;right:0;height:3px;z-index:9000;
  background:transparent;pointer-events:none;
  opacity:0;transition:opacity var(--t) var(--ease);
}
#topProgress.on{opacity:1}
#topProgress .bar{
  height:100%;width:40%;border-radius:0 3px 3px 0;
  background:linear-gradient(90deg,transparent,var(--purple2) 25%,var(--purple) 60%,#e9d5ff);
  box-shadow:0 0 12px rgba(139,92,246,.75);
  animation:tp 1.15s var(--ease) infinite;
}
@keyframes tp{
  0%{transform:translateX(-100%) scaleX(.6)}
  55%{transform:translateX(60%) scaleX(1)}
  100%{transform:translateX(250%) scaleX(.5)}
}

/* ---------- 2. Blur / glass busy overlay ---------- */
#busyOverlay{
  position:fixed;inset:0;z-index:8500;
  display:flex;align-items:center;justify-content:center;
  background:var(--glass);
  -webkit-backdrop-filter:blur(9px) saturate(120%);
  backdrop-filter:blur(9px) saturate(120%);
  opacity:0;visibility:hidden;
  transition:opacity var(--t) var(--ease),visibility var(--t) step-end;
}
#busyOverlay.on{opacity:1;visibility:visible;transition:opacity var(--t) var(--ease),visibility 0s}
#busyOverlay .busy-card{
  min-width:320px;max-width:min(560px,92vw);
  padding:26px 28px;border-radius:20px;
  background:var(--panel);border:1px solid var(--line);
  box-shadow:0 30px 80px rgba(0,0,0,.45);
  text-align:center;
  transform:translateY(10px) scale(.97);
  transition:transform var(--t-slow) var(--ease-out);
}
#busyOverlay.on .busy-card{transform:translateY(0) scale(1)}
.busy-title{font-weight:750;font-size:16px;margin:14px 0 4px}
.busy-sub{color:var(--muted);font-size:13px;line-height:1.55}
.busy-elapsed{font-variant-numeric:tabular-nums;color:var(--purple2);font-weight:700}
.busy-hint{
  margin-top:14px;padding:10px 12px;border-radius:10px;font-size:12.5px;
  background:rgba(246,196,83,.10);border:1px solid rgba(246,196,83,.28);
  color:var(--text);text-align:left;
  opacity:0;max-height:0;overflow:hidden;
  transition:opacity var(--t) var(--ease),max-height var(--t-slow) var(--ease),margin-top var(--t) var(--ease);
}
.busy-hint.on{opacity:1;max-height:160px}
.busy-steps{
  margin-top:16px;text-align:left;display:flex;flex-direction:column;gap:7px;
  font-size:12.5px;color:var(--muted);
}
.busy-step{display:flex;align-items:center;gap:9px;transition:color var(--t) var(--ease)}
.busy-step .dot{
  width:8px;height:8px;border-radius:50%;background:var(--line);flex:0 0 8px;
  transition:background var(--t) var(--ease),box-shadow var(--t) var(--ease);
}
.busy-step.active{color:var(--text);font-weight:650}
.busy-step.active .dot{background:var(--purple);box-shadow:0 0 0 4px rgba(139,92,246,.20)}
.busy-step.done .dot{background:var(--good)}
.busy-step.done{color:var(--muted)}

/* Spinner: one shape reused everywhere */
.spinner{
  width:34px;height:34px;border-radius:50%;
  border:3px solid var(--line);border-top-color:var(--purple);
  animation:spin .75s linear infinite;margin:0 auto;
}
.spinner.sm{width:14px;height:14px;border-width:2px;display:inline-block;vertical-align:-2px;margin:0}
@keyframes spin{to{transform:rotate(360deg)}}

/* ---------- 3. Toasts ---------- */
#toasts{
  position:fixed;right:18px;bottom:18px;z-index:9500;
  display:flex;flex-direction:column;gap:10px;
  width:min(400px,calc(100vw - 36px));pointer-events:none;
}
.toast{
  pointer-events:auto;position:relative;overflow:hidden;
  display:flex;gap:11px;padding:13px 14px;
  border-radius:13px;border:1px solid var(--line);
  background:var(--panel2);box-shadow:0 18px 44px rgba(0,0,0,.40);
  transform:translateX(120%);opacity:0;
  transition:transform var(--t-slow) var(--ease-out),opacity var(--t) var(--ease),margin var(--t) var(--ease);
}
.toast.in{transform:translateX(0);opacity:1}
.toast.out{transform:translateX(120%);opacity:0;margin-bottom:-58px}
.toast .ic{flex:0 0 20px;font-size:15px;line-height:1.35;font-weight:800}
.toast .body{flex:1;min-width:0}
.toast .t{font-weight:700;font-size:13.5px;margin-bottom:2px}
.toast .m{font-size:12.5px;color:var(--muted);line-height:1.5;word-break:break-word}
.toast .x{
  flex:0 0 auto;background:none;border:0;color:var(--muted);cursor:pointer;
  font-size:16px;line-height:1;padding:0 2px;border-radius:6px;
  transition:color var(--t-fast) var(--ease),background var(--t-fast) var(--ease);
}
.toast .x:hover{color:var(--text);background:rgba(255,255,255,.07)}
.toast .life{position:absolute;left:0;bottom:0;height:2px;width:100%;transform-origin:left}
.toast.success{border-color:rgba(56,217,150,.42)}
.toast.success .ic{color:var(--good)} .toast.success .life{background:var(--good)}
.toast.info{border-color:rgba(167,139,250,.42)}
.toast.info .ic{color:var(--purple2)} .toast.info .life{background:var(--purple2)}
.toast.warn{border-color:rgba(246,196,83,.48)}
.toast.warn .ic{color:var(--warn)} .toast.warn .life{background:var(--warn)}
.toast.error{border-color:rgba(255,113,132,.52)}
.toast.error .ic{color:var(--bad)} .toast.error .life{background:var(--bad)}
.toast .act{
  margin-top:9px;background:rgba(255,255,255,.06);border:1px solid var(--line);
  color:var(--text);font-size:12px;font-weight:650;padding:5px 11px;border-radius:8px;cursor:pointer;
  transition:background var(--t-fast) var(--ease),transform var(--t-fast) var(--ease);
}
.toast .act:hover{background:rgba(255,255,255,.12)}
.toast .act:active{transform:translateY(1px)}

/* ---------- 4. Status bar ---------- */
.statusbar{
  display:flex;align-items:center;gap:10px;margin-top:12px;
  padding:11px 13px;border-radius:12px;
  background:var(--panel2);border:1px solid var(--line);
  transition:border-color var(--t) var(--ease),background var(--t) var(--ease);
}
.statusbar .status-icon{
  flex:0 0 auto;width:18px;height:18px;display:grid;place-items:center;
  font-size:12px;font-weight:800;color:var(--muted);
}
/* #status keeps its legacy .status class so existing S.textContent calls
   still work; neutralise its own box so it does not nest inside the bar. */
.statusbar .status{flex:1;min-width:0;font-size:13px;line-height:1.5;margin:0;padding:0;background:none;border:0;border-radius:0;color:inherit}
.light .statusbar .status{color:inherit}
.statusbar .status-time{
  flex:0 0 auto;font-size:11.5px;color:var(--muted);
  font-variant-numeric:tabular-nums;white-space:nowrap;
}
.statusbar.busy{border-color:rgba(167,139,250,.50);background:rgba(139,92,246,.08)}
.statusbar.busy .status-icon{color:var(--purple2)}
.statusbar.success{border-color:rgba(56,217,150,.42)}
.statusbar.success .status-icon{color:var(--good)}
.statusbar.warn{border-color:rgba(246,196,83,.46);background:rgba(246,196,83,.07)}
.statusbar.warn .status-icon{color:var(--warn)}
.statusbar.error{border-color:rgba(255,113,132,.50);background:rgba(255,113,132,.07)}
.statusbar.error .status-icon{color:var(--bad)}

/* ---------- 5. Connection badge ---------- */
.badge.conn{display:inline-flex;align-items:center;gap:8px;transition:all var(--t) var(--ease)}
.badge.conn .dot{width:8px;height:8px;border-radius:50%;background:var(--muted);flex:0 0 8px}
.badge.conn.ok .dot{background:var(--good);box-shadow:0 0 0 4px rgba(56,217,150,.18)}
.badge.conn.bad .dot{background:var(--bad);box-shadow:0 0 0 4px rgba(255,113,132,.18)}
.badge.conn.testing .dot{background:var(--warn);animation:pulse 1.1s var(--ease) infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.32}}

/* ---------- 6. Skeletons ---------- */
.skel{
  position:relative;overflow:hidden;border-radius:8px;
  background:linear-gradient(90deg,rgba(255,255,255,.045) 0%,rgba(255,255,255,.10) 50%,rgba(255,255,255,.045) 100%);
  background-size:220% 100%;animation:shimmer 1.35s var(--ease) infinite;
}
.light .skel{background:linear-gradient(90deg,rgba(0,0,0,.05) 0%,rgba(0,0,0,.10) 50%,rgba(0,0,0,.05) 100%);background-size:220% 100%}
@keyframes shimmer{0%{background-position:120% 0}100%{background-position:-120% 0}}
.skel-line{height:12px;margin:9px 0}
.skel-row{display:flex;gap:10px;padding:11px 0;border-bottom:1px solid var(--line)}
.skel-row>.skel{height:12px;flex:1}
.skel-card{padding:16px;border:1px solid var(--line);border-radius:var(--radius);background:var(--card)}

/* ---------- 7. Empty & error states ---------- */
.state{
  text-align:center;padding:44px 24px;border-radius:var(--radius);
  border:1px dashed var(--line);background:rgba(255,255,255,.018);
  animation:fadeUp var(--t-slow) var(--ease-out) both;
}
.state .ic{font-size:30px;opacity:.5;margin-bottom:10px}
.state h4{margin:0 0 6px;font-size:15px}
.state p{margin:0 auto;max-width:460px;color:var(--muted);font-size:13px;line-height:1.6}
.state button{margin-top:16px}
.state.err{border-style:solid;border-color:rgba(255,113,132,.42);background:rgba(255,113,132,.055)}
.state.err .ic{color:var(--bad);opacity:1}
.state pre{
  margin:14px auto 0;max-width:100%;overflow:auto;text-align:left;
  background:var(--input);border:1px solid var(--line);border-radius:10px;
  padding:11px 13px;font-size:11.5px;color:var(--muted);white-space:pre-wrap;
}
@keyframes fadeUp{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}

/* ---------- 8. Data-quality banner ---------- */
.dq{
  margin:14px 0;padding:13px 15px;border-radius:12px;display:flex;gap:11px;
  border:1px solid rgba(246,196,83,.34);background:rgba(246,196,83,.075);
  animation:fadeUp var(--t-slow) var(--ease-out) both;
}
.dq .ic{flex:0 0 auto;color:var(--warn);font-weight:800}
.dq h4{margin:0 0 5px;font-size:13.5px}
.dq ul{margin:0;padding-left:17px;font-size:12.5px;color:var(--muted);line-height:1.65}

/* ---------- 9. Buttons: busy + press feedback ---------- */
button{transition:background var(--t-fast) var(--ease),border-color var(--t-fast) var(--ease),
        transform var(--t-fast) var(--ease),opacity var(--t-fast) var(--ease),box-shadow var(--t-fast) var(--ease)}
button:not(:disabled):active{transform:translateY(1px)}
button:disabled{opacity:.55;cursor:not-allowed}
button[data-busy="1"]{position:relative;color:transparent!important;pointer-events:none}
button[data-busy="1"]::after{
  content:"";position:absolute;inset:0;margin:auto;
  width:15px;height:15px;border-radius:50%;
  border:2px solid rgba(255,255,255,.35);border-top-color:#fff;
  animation:spin .7s linear infinite;
}
:focus-visible{outline:2px solid var(--purple2);outline-offset:2px;border-radius:8px}

/* ---------- 10. Page transitions ---------- */
.page{display:none}
.page.active{display:block;animation:pageIn var(--t-slow) var(--ease-out) both}
@keyframes pageIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
.card,.panel{transition:border-color var(--t) var(--ease),box-shadow var(--t) var(--ease),transform var(--t) var(--ease)}
.drill-card{cursor:pointer}
.drill-card:hover{transform:translateY(-2px);box-shadow:0 12px 28px rgba(0,0,0,.28);border-color:rgba(167,139,250,.45)}
.menu button{transition:background var(--t-fast) var(--ease),color var(--t-fast) var(--ease),padding-left var(--t-fast) var(--ease)}
.menu button:hover:not(.active){padding-left:18px}
tbody tr{transition:background var(--t-fast) var(--ease)}

/* ---------- 11. Tables: sticky header + scroll affordance ---------- */
.table-wrap{
  overflow:auto;-webkit-overflow-scrolling:touch;
  border-radius:12px;border:1px solid var(--line);
  max-height:min(70vh,720px);
  scrollbar-width:thin;
}
.table-wrap::-webkit-scrollbar{height:9px;width:9px}
.table-wrap::-webkit-scrollbar-thumb{background:var(--line);border-radius:9px}
.table-wrap::-webkit-scrollbar-thumb:hover{background:var(--purple)}
.table-wrap thead th{
  position:sticky;top:0;z-index:2;
  background:var(--panel2);
  box-shadow:inset 0 -1px 0 var(--line);
  backdrop-filter:blur(6px);
}

/* ---------- 12. Responsive shell ---------- */
#navToggle{display:none}
@media(max-width:900px){
  #navToggle{
    display:inline-flex;align-items:center;gap:8px;
    position:fixed;left:12px;top:11px;z-index:8000;
    padding:9px 13px;border-radius:11px;font-size:13px;font-weight:700;
    background:var(--panel);border:1px solid var(--line);color:var(--text);
    box-shadow:0 8px 22px rgba(0,0,0,.32);cursor:pointer;
  }
  .app{grid-template-columns:1fr!important;display:block!important}
  .sidebar{
    position:fixed!important;inset:0 auto 0 0;width:266px;height:100%!important;z-index:8200;
    transform:translateX(-102%);transition:transform var(--t-slow) var(--ease-out);
    box-shadow:0 0 60px rgba(0,0,0,.5);overflow:auto;
  }
  body.nav-open .sidebar{transform:translateX(0)}
  body.nav-open::after{
    content:"";position:fixed;inset:0;z-index:8100;
    background:rgba(0,0,0,.5);-webkit-backdrop-filter:blur(3px);backdrop-filter:blur(3px);
  }
  .sidebar .menu{flex-direction:column!important;overflow:visible!important}
  .sidebar-bottom{display:block!important}
  .main{padding:62px 14px 26px!important}
  .header{flex-direction:column;align-items:flex-start;gap:10px}
  .header h1{font-size:20px;line-height:1.3}
  .controls{flex-direction:column;align-items:stretch}
  .controls>*{width:100%}
  .controls select,.controls button{width:100%}
  .cards{grid-template-columns:1fr!important}
  .inline-findings-grid{grid-template-columns:1fr!important}
  .access-summary-grid{grid-template-columns:repeat(2,minmax(0,1fr))!important}
  #toasts{right:10px;left:10px;bottom:10px;width:auto}
  .table-wrap{max-height:none}
  .table-wrap thead th{position:static}
  #busyOverlay .busy-card{min-width:0;width:calc(100vw - 32px);padding:22px}
}
@media(max-width:520px){
  .access-summary-grid{grid-template-columns:1fr!important}
  .state{padding:32px 16px}
}

/* ---------- 12b. Grid shrink fix ----------
   `1fr` is shorthand for minmax(auto,1fr), and `auto` refuses to shrink below
   the content's min-width. One table with min-width:650px therefore stretched
   its grid column to 688px and forced the whole document to scroll sideways on
   a 390px screen. minmax(0,1fr) plus min-width:0 down the chain lets
   .table-wrap do the scrolling instead of the page, so wide tables stay
   readable and the layout still fits. */
.cards,.dashboard-grid,.inline-findings-grid,.access-summary-grid{min-width:0}
.cards>*,.dashboard-grid>*,.inline-findings-grid>*,.access-summary-grid>*{min-width:0}
.panel,.card,.main,.section-title{min-width:0}
.table-wrap{min-width:0;max-width:100%}
.section-title{flex-wrap:wrap;gap:8px}
.flow{flex-wrap:wrap}
@media(max-width:900px){
  .dashboard-grid{grid-template-columns:minmax(0,1fr)!important}
  .cards{grid-template-columns:minmax(0,1fr)!important}
  .inline-findings-grid{grid-template-columns:minmax(0,1fr)!important}
  .access-summary-grid{grid-template-columns:repeat(2,minmax(0,1fr))!important}
  .flow .arrow{display:none}
  .flow .step{width:100%}
}

/* ---------- 13. Offline / stale ---------- */
#offlineBar{
  position:fixed;left:50%;top:12px;transform:translate(-50%,-160%);
  z-index:9600;padding:9px 16px;border-radius:999px;
  background:rgba(255,113,132,.16);border:1px solid rgba(255,113,132,.5);
  color:var(--text);font-size:12.5px;font-weight:650;
  -webkit-backdrop-filter:blur(8px);backdrop-filter:blur(8px);
  transition:transform var(--t-slow) var(--ease-out);
}
#offlineBar.on{transform:translate(-50%,0)}
.stale{position:relative}
.stale::after{
  content:"stale";position:absolute;right:10px;top:10px;
  font-size:10px;font-weight:800;letter-spacing:.04em;text-transform:uppercase;
  padding:3px 7px;border-radius:6px;color:var(--warn);
  background:rgba(246,196,83,.14);border:1px solid rgba(246,196,83,.34);
}

/* Screen-reader-only live region */
.sr-only{
  position:absolute;width:1px;height:1px;padding:0;margin:-1px;
  overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0;
}

</style>
</head>
<body>
<div id="topProgress" aria-hidden="true"><div class="bar"></div></div>
<div id="offlineBar">You are offline — requests will fail until the connection returns</div>
<div id="toasts" aria-live="polite" aria-relevant="additions"></div>
<div id="srLive" class="sr-only" role="status" aria-live="polite"></div>
<button id="navToggle" onclick="toggleNav()" aria-label="Toggle navigation">&#9776; Menu</button>
<div id="busyOverlay" role="dialog" aria-modal="true" aria-live="assertive">
  <div class="busy-card">
    <div class="spinner"></div>
    <div class="busy-title" id="busyTitle">Working…</div>
    <div class="busy-sub" id="busySub"></div>
    <div class="busy-steps" id="busySteps"></div>
    <div class="busy-hint" id="busyHint"></div>
  </div>
</div>
<div class="app">
  <aside class="sidebar">
    <div class="brand">Firewall <span>Insight</span></div>
    <div class="menu">
      <button class="active" data-page="dashboard" onclick="showPage('dashboard',this)">◈ Dashboard</button>
      <button data-page="browser" onclick="showPage('browser',this)">▤ Access Policy</button>
      <button data-page="access" onclick="showPage('access',this)">◇ Analyze</button>
      <button data-page="nat" onclick="showPage('nat',this)">⇄ NAT Policy</button>
      <button data-page="traffic" onclick="showPage('traffic',this)">➜ Traffic Path</button>
      <button data-page="mapping" onclick="showPage('mapping',this)">⌘ Network Mapping</button>

    </div>
    <div class="sidebar-bottom">
      <div class="theme-row"><span>Light Mode</span><span class="switch" onclick="toggleTheme()"><i></i></span></div>
      <div class="hint" style="padding:8px">Read-only · Management API</div>
    </div>
  </aside>

  <main class="main">
    <div class="header">
      <div><h1>Check Point Firewall Analysis Platform</h1></div>
      <div id="conn" class="badge conn"><span class="dot"></span><span>Not tested</span></div>
    </div>

    <div class="panel">
      <div class="controls">
        <button onclick="testConn(event)">Test Connection</button>
        <button onclick="loadMetadata(true,event)">Refresh Metadata</button>
        <span id="layerControl"><select id="layer"><option value="">Select Access Layer...</option></select></span>
        <span id="packageControl"><select id="pkg"><option value="">Select Policy Package...</option></select></span>
      </div>
      <div class="statusbar" id="statusBar"><span class="status-icon" id="statusIcon">•</span><div id="status" class="status">Ready. No API calls are made automatically.</div><span class="status-time" id="statusTime"></span></div>
    </div>

    <section id="dashboard" class="page active">
      <div class="panel">
        <div class="section-title">
          <div>
            <h2>Security Policy Overview</h2>
            <p class="muted" style="margin:6px 0 0">Summary of the latest Access and NAT analysis in this browser session.</p>
          </div>
          <button class="primary" onclick="dashboardRefresh()">Analyze Selected Policies</button>
        </div>

        <div id="dashboardCards" class="cards">
          <div class="card drill-card" onclick="drillTo('browser')" title="Open Policy Browser"><div class="metric-label">Access Rules</div><div id="dAccess" class="metric">—</div><div id="dAccessDetail" class="hint">Selected Access Layer</div></div>
          <div class="card drill-card" onclick="drillTo('access','shadow')" title="Open Shadow / Redundant"><div class="metric-label">Shadow / Redundant</div><div id="dShadow" class="metric">—</div><div class="hint">Review candidates</div></div>
          <div class="card drill-card" onclick="drillTo('access','duplicates')" title="Open Duplicate Access"><div class="metric-label">Duplicate Access</div><div id="dDup" class="metric">—</div><div class="hint">Exact duplicate groups</div></div>
          <div class="card drill-card" onclick="drillTo('nat','rulebase')" title="Open NAT Rulebase"><div class="metric-label">NAT Rules</div><div id="dNat" class="metric">—</div><div class="hint">Selected Policy Package</div></div>
          <div class="card drill-card" onclick="drillTo('nat','duplicates')" title="Open Duplicate NAT"><div class="metric-label">Duplicate NAT</div><div id="dNatDup" class="metric">—</div><div class="hint">Exact duplicate groups</div></div>
        </div>

        <div id="inlineAnalysisSummary" class="inline-findings-card" style="display:none">
          <div class="section-title" style="margin:0">
            <h3 style="margin:0">Inline Layer Analysis</h3>
            <span class="hint">Included in the overall Access analysis</span>
          </div>
          <div class="inline-findings-grid">
            <div class="inline-mini"><div class="hint">Inline Layers</div><div id="diLayers" class="v">0</div></div>
            <div class="inline-mini"><div class="hint">Inline Rules Inspected</div><div id="diRules" class="v">0</div></div>
            <div class="inline-mini drill-card" onclick="drillTo('access','shadow')" title="Open inline Shadow / Redundant findings"><div class="hint">Shadow / Redundant</div><div id="diShadow" class="v">0</div></div>
            <div class="inline-mini drill-card" onclick="drillTo('access','duplicates')" title="Open inline Duplicate findings"><div class="hint">Duplicate Groups</div><div id="diDup" class="v">0</div></div>
            <div class="inline-mini drill-card" onclick="drillTo('access','any')" title="Open inline Any / Any / Any findings"><div class="hint">Any / Any / Any</div><div id="diAny" class="v">0</div></div>
          </div>
        </div>

        <div class="dashboard-grid" style="display:grid;grid-template-columns:1.35fr .9fr;gap:14px;margin-top:18px">
          <div class="card">
            <div class="section-title"><h3>Optimization Findings</h3><span class="hint">Latest Access analysis</span></div>
            <div id="dashFindings" class="table-wrap" style="margin-top:12px">
              <table style="min-width:650px">
                <thead><tr><th>Finding</th><th>Count</th><th>Meaning</th></tr></thead>
                <tbody>
                  <tr><td>Shadow / Redundant</td><td>—</td><td>Run Access analysis to populate.</td></tr>
                  <tr><td>Duplicate Access</td><td>—</td><td>Run Access analysis to populate.</td></tr>
                  <tr><td>Any / Any / Any</td><td>—</td><td>Run Access analysis to populate.</td></tr>
                </tbody>
              </table>
            </div>
          </div>

          <div class="card">
            <h3 style="margin-top:0">Quick Actions</h3>
            <div style="display:grid;gap:9px;margin-top:14px">
              <button class="primary" onclick="goTo('browser')">Open Access Policy</button>
              <button onclick="goTo('access')">Open Analyze</button>
              <button onclick="goTo('nat')">Analyze NAT Policy</button>
              <button onclick="goTo('traffic')">Trace Source → Destination</button>
              <button onclick="goTo('mapping')">Open Network Topology</button>
            </div>
            <div class="hint" style="margin-top:16px">The tool remains read-only and does not publish or install policy.</div>
          </div>
        </div>

        <div class="card" style="margin-top:14px">
          <div class="section-title"><h3>Selected Context</h3><span class="hint">Change from Access/NAT pages</span></div>
          <div class="table-wrap" style="margin-top:12px">
            <table style="min-width:650px">
              <tr><th>Access Layer</th><th>Policy Package</th><th>Management API</th><th>Mode</th></tr>
              <tr><td id="dashLayer">Not selected</td><td id="dashPackage">Not selected</td><td id="dashApi">Not tested</td><td><span class="pill good">Read-only</span></td></tr>
            </table>
          </div>
        </div>
      </div>
    </section>

    <section id="browser" class="page">
      <div class="panel">
        <div class="section-title">
          <div>
            <h2>Access Policy</h2>
            <p class="muted" style="margin:6px 0 0">
              Configured Access Control policy as-is.
            </p>
          </div>
          <span id="browserCount" class="pill purple">Not loaded</span>
        </div>

        <div class="controls" style="margin-top:16px">
          <button id="browserBtn" class="primary" onclick="loadPolicyBrowser()">Load Policy</button>
          <button onclick="exportRawPolicy()">Export Raw CSV</button>
          <input id="policySearch" placeholder="Search rule, object, service, action..." oninput="filterPolicyBrowser()" style="min-width:310px">
          <select id="actionFilter" onchange="filterPolicyBrowser()" style="min-width:150px">
            <option value="">All Actions</option>
            <option value="accept">Accept</option>
            <option value="drop">Drop</option>
            <option value="reject">Reject</option>
          </select>
        </div>

        <div id="browserSummary" class="cards access-summary-grid hidden"></div>
        <div id="browserDq"></div>
        <div id="browserResults" style="margin-top:18px"></div>
      </div>
    </section>

    <section id="access" class="page">
      <div class="panel">
        <div class="section-title">
          <div>
            <h2>Analyze</h2>
            <p class="muted" style="margin:6px 0 16px">
              Optimizer analysis for the selected Access Layer.
            </p>
          </div>
          <button id="accessBtn" class="primary" onclick="runAccess()">Analyze Access Policy</button>
        </div>

        <div id="accessCards" class="cards hidden"></div>
        <div id="accessDq"></div>
        <div id="accessFindings"></div>
      </div>
    </section>

    <section id="nat" class="page">
      <div class="panel">
        <div class="controls"><button id="natBtn" class="primary" onclick="runNat()">Analyze NAT Policy</button></div>
        <div id="natCards" class="cards hidden"></div>
        <div class="tabs" id="natTabs" style="display:none">
          <button class="active" onclick="showNatTab('rulebase',this)">NAT Rulebase</button>
          <button onclick="showNatTab('duplicates',this)">Duplicate NAT</button>
          <button onclick="showNatTab('broad',this)">Broad NAT Rules</button>
        <button onclick="showNatTab('disabled',this)">Disabled NAT <span id="nat-disabled-tab-count"></span></button>
          <button onclick="showNatTab('notrans',this)">Possible No-Translation <span id="nat-notrans-tab-count"></span></button>
        </div>
        <div id="natResults"></div>
      
        <div id="nat-disabled-view" style="display:none">
          <h3>Disabled NAT Rules</h3>
          <div class="table-wrap"><table>
            <thead><tr><th>Rule</th><th>Name</th><th>Original Source</th><th>Original Destination</th><th>Original Service</th><th>Method</th></tr></thead>
            <tbody id="nat-disabled-body"></tbody>
          </table></div>
        </div>
        <div id="nat-notrans-view" style="display:none">
          <h3>Possible No-Translation</h3>
          <p class="muted">Rules where all translated fields remain Original / unchanged. Review before deciding whether the rule is unnecessary.</p>
          <div class="table-wrap"><table>
            <thead><tr><th>Rule</th><th>Name</th><th>Original Source</th><th>Original Destination</th><th>Original Service</th><th>Translated Source</th><th>Translated Destination</th><th>Translated Service</th></tr></thead>
            <tbody id="nat-notrans-body"></tbody>
          </table></div>
        </div>
</div>
    </section>

    <section id="traffic" class="page">
      <div class="panel">
        <h2>Traffic Path Analyzer</h2>
        <div class="controls">
          <input id="src" placeholder="Source IP / Domain">
          <input id="dst" placeholder="Destination IP / Domain">
          <select id="proto" style="min-width:110px"><option>tcp</option><option>udp</option></select>
          <input id="port" type="text" placeholder="Port / Service (443, https, ssh)">
          <button class="primary" onclick="trace()">Analyze Path</button>
        </div>
        <div id="traceResult"></div>
      </div>
    </section>

    <section id="mapping" class="page">
      <div class="panel">
        <div class="section-title"><h2>Network Mapping</h2><div><button class="primary" onclick="loadMap(event)">Load Topology</button> <button onclick="mapMode('topology')">Topology</button> <button onclick="mapMode('inventory')">Inventory</button></div></div>
        <p class="muted">Logical topology: Gateway → Interface → Connected Subnet. Physical cabling and live routing are not inferred.</p>
        <div id="topology" class="topology"><div class="muted" style="padding:25px">Click Load Topology.</div></div>
        <div id="inventory" class="map hidden"></div>
        <p id="mapNote" class="hint"></p>
      </div>
    </section>


  </main>
</div>

<script>
const S=document.getElementById('status'), L=document.getElementById('layer'), P=document.getElementById('pkg');
let browserData=null,accessData=null,natData=null,mapData=null;

function renderDataQuality(id,dq){
  const el=document.getElementById(id);
  if(el) el.innerHTML=dataQualityBanner(dq);
}

function primeEmptyStates(){
  const pkgHint='Pick a Policy Package at the top of the page, then run the analysis. Nothing is fetched until you ask.';
  const put=(id,html)=>{const el=document.getElementById(id); if(el&&!el.innerHTML.trim()) el.innerHTML=html;};
  put('browserResults',emptyState('\u25a4','No policy loaded yet',pkgHint,'Load Policy','onclick="loadPolicyBrowser()"'));
  put('accessFindings',emptyState('\u25c7','No analysis yet',pkgHint,'Run Analysis','onclick="runAccess()"'));
  put('traceResult',emptyState('\u279c','No trace yet','Enter a source, a destination and a port or service, then run the trace. This is a configuration-based simulation \u2014 it never sends a packet, so the hosts do not need to exist.',null,null));
}

function esc(v){return String(v??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]))}

/* ============================================================
   v4.11 UX runtime.

   The problem this replaces: every long call ran silently and the only
   feedback was one line of text, so "working", "finished" and "crashed"
   looked identical and you had to open DevTools to tell them apart.

   Design rules:
     - every request is tracked, so activity is always visible
     - every failure surfaces in the UI, never only in the console
     - anything slow reports elapsed time, so it never looks frozen
     - a partial result is labelled partial, never shown as complete
   ============================================================ */

const UX_LONG_MS = 6000;      // when to explain that slowness is expected
const UX_TIMEOUT_MS = 240000; // hard ceiling; hydration on a big policy is slow

/* ---------- status bar ---------- */
const STATUS_ICONS = {info:'•', busy:'', success:'✓', warn:'!', error:'✕'};

function setStatus(msg, kind='info'){
  const bar = document.getElementById('statusBar');
  const icon = document.getElementById('statusIcon');
  const time = document.getElementById('statusTime');
  if(S) S.textContent = msg;
  if(bar) bar.className = 'statusbar' + (kind !== 'info' ? ' ' + kind : '');
  if(icon) icon.innerHTML = kind === 'busy'
    ? '<span class="spinner sm"></span>'
    : (STATUS_ICONS[kind] || '•');
  if(time) time.textContent = new Date().toLocaleTimeString();
  const live = document.getElementById('srLive');
  if(live && kind !== 'busy') live.textContent = msg;
}

/* ---------- toasts ---------- */
const TOAST_ICONS = {success:'✓', info:'i', warn:'!', error:'✕'};
const TOAST_LIFE = {success:4200, info:5200, warn:9000, error:0}; // 0 = sticky

function notify(kind, title, message='', opts={}){
  const host = document.getElementById('toasts');
  if(!host) return;
  const el = document.createElement('div');
  el.className = 'toast ' + kind;
  el.setAttribute('role', kind === 'error' ? 'alert' : 'status');

  const life = opts.duration !== undefined ? opts.duration : TOAST_LIFE[kind];
  el.innerHTML =
    `<div class="ic">${TOAST_ICONS[kind] || 'i'}</div>` +
    `<div class="body"><div class="t">${esc(title)}</div>` +
    (message ? `<div class="m">${esc(message)}</div>` : '') +
    (opts.actionLabel ? `<button class="act">${esc(opts.actionLabel)}</button>` : '') +
    `</div><button class="x" aria-label="Dismiss">×</button>` +
    (life ? `<div class="life"></div>` : '');

  host.appendChild(el);
  requestAnimationFrame(() => el.classList.add('in'));

  const close = () => {
    if(el.dataset.closing) return;
    el.dataset.closing = '1';
    el.classList.add('out');
    setTimeout(() => el.remove(), 400);
  };
  el.querySelector('.x').onclick = close;
  const act = el.querySelector('.act');
  if(act && opts.onAction) act.onclick = () => { close(); opts.onAction(); };

  if(life){
    const bar = el.querySelector('.life');
    bar.style.transition = `transform ${life}ms linear`;
    requestAnimationFrame(() => { bar.style.transform = 'scaleX(0)'; });
    setTimeout(close, life);
  }
  return close;
}

/* ---------- global request tracking ---------- */
let uxInFlight = 0;

function uxRequestStart(){
  uxInFlight++;
  const p = document.getElementById('topProgress');
  if(p) p.classList.add('on');
  document.body.setAttribute('aria-busy', 'true');
}
function uxRequestEnd(){
  uxInFlight = Math.max(0, uxInFlight - 1);
  if(uxInFlight === 0){
    const p = document.getElementById('topProgress');
    if(p) p.classList.remove('on');
    document.body.removeAttribute('aria-busy');
  }
}

/* ---------- blocking overlay ---------- */
let uxBusyTimer = null, uxBusyStart = 0, uxBusyDepth = 0;

function busyShow(title, sub='', steps=[]){
  uxBusyDepth++;
  const ov = document.getElementById('busyOverlay');
  if(!ov) return;
  document.getElementById('busyTitle').textContent = title;
  document.getElementById('busySub').innerHTML =
    esc(sub) + ' <span class="busy-elapsed" id="busyElapsed">0.0s</span>';
  const hint = document.getElementById('busyHint');
  hint.classList.remove('on');
  const stepBox = document.getElementById('busySteps');
  stepBox.innerHTML = steps.map((s, i) =>
    `<div class="busy-step${i === 0 ? ' active' : ''}" data-step="${i}">` +
    `<span class="dot"></span><span>${esc(s)}</span></div>`).join('');

  ov.classList.add('on');
  uxBusyStart = Date.now();
  clearInterval(uxBusyTimer);
  uxBusyTimer = setInterval(() => {
    const ms = Date.now() - uxBusyStart;
    const e = document.getElementById('busyElapsed');
    if(e) e.textContent = (ms / 1000).toFixed(1) + 's';
    if(ms > UX_LONG_MS && !hint.classList.contains('on')){
      hint.classList.add('on');
      hint.textContent = 'Still working. The first load of a package fetches '
        + 'full object detail one object at a time, paced to stay under the '
        + 'Management API rate limit, so 10–20s is normal. Results are '
        + 'then cached for 5 minutes.';
    }
  }, 100);
}

function busyStep(index){
  document.querySelectorAll('#busySteps .busy-step').forEach(el => {
    const i = Number(el.dataset.step);
    el.classList.toggle('active', i === index);
    el.classList.toggle('done', i < index);
  });
}

function busyHide(){
  uxBusyDepth = Math.max(0, uxBusyDepth - 1);
  if(uxBusyDepth > 0) return;
  clearInterval(uxBusyTimer);
  const ov = document.getElementById('busyOverlay');
  if(ov) ov.classList.remove('on');
}

/* ---------- error normalisation ---------- */
function describeError(e){
  const raw = String((e && e.message) || e || 'Unknown error');
  if(e && e.name === 'AbortError')
    return {title:'Request timed out', hint:'The Management API did not answer in time. It may be busy loading a large policy — try again, or raise CHECKPOINT_TIMEOUT.'};
  if(/failed to fetch|networkerror|load failed/i.test(raw))
    return {title:'Cannot reach Firewall Insight', hint:'The uvicorn server looks like it stopped. Check the terminal running it, then retry.'};
  if(/^HTTP 429|rate limit|too many requests/i.test(raw))
    return {title:'Management API rate limit', hint:'Retry/backoff was exhausted. Wait a moment and retry, or raise CHECKPOINT_MIN_REQUEST_INTERVAL in .env.'};
  if(/^HTTP 502|unable to connect/i.test(raw))
    return {title:'Management Server unreachable', hint:'Check CHECKPOINT_MGMT in .env, that the server is up, and that the Management API accepts this client.'};
  if(/^HTTP 400/i.test(raw))
    return {title:'Request rejected', hint:raw.replace(/^HTTP 400:\s*/i, '')};
  if(/login|authentication|credential/i.test(raw))
    return {title:'Authentication failed', hint:'Check CHECKPOINT_USER and CHECKPOINT_PASSWORD in .env.'};
  return {title:'Request failed', hint:raw};
}

function fail(e, context=''){
  const d = describeError(e);
  const raw = String((e && e.message) || e || '');
  setStatus((context ? context + ': ' : '') + d.title + ' — ' + d.hint, 'error');
  notify('error', d.title, d.hint, {
    actionLabel: 'Copy details',
    onAction: () => {
      const text = (context ? context + '\n' : '') + raw;
      if(navigator.clipboard) navigator.clipboard.writeText(text);
      notify('info', 'Copied', 'Error details are on your clipboard.');
    }
  });
  console.error('[Firewall Insight]', context, e);
  return d;
}

/* ---------- the task wrapper ---------- */
const uxRunning = new Set();

async function task(key, label, fn, opts={}){
  if(uxRunning.has(key)){
    notify('info', 'Already running', label + ' is still in progress.');
    return;
  }
  uxRunning.add(key);
  const btn = opts.button || null;
  if(btn){ btn.dataset.busy = '1'; btn.disabled = true; }
  setStatus(label + '…', 'busy');
  if(opts.blocking !== false) busyShow(label, opts.sub || 'Elapsed', opts.steps || []);

  try{
    const out = await fn();
    if(opts.successMessage !== null){
      setStatus(opts.successMessage || (label + ' complete.'), 'success');
      if(opts.toast !== false)
        notify('success', opts.successTitle || label + ' complete', opts.successMessage || '');
    }
    return out;
  }catch(e){
    fail(e, label);
    throw e;
  }finally{
    uxRunning.delete(key);
    if(btn){ delete btn.dataset.busy; btn.disabled = false; }
    if(opts.blocking !== false) busyHide();
  }
}

/* ---------- skeletons / states ---------- */
function skeletonTable(cols=7, rows=8){
  return '<div class="table-wrap" style="padding:4px 14px 14px">'
    + `<div class="skel-row">${'<div class="skel"></div>'.repeat(cols)}</div>`.repeat(rows + 1)
    + '</div>';
}
function skeletonCards(n=5){
  return `<div class="cards">${
    '<div class="skel-card"><div class="skel skel-line" style="width:52%"></div>'
    + '<div class="skel skel-line" style="height:26px;width:38%"></div>'
    + '<div class="skel skel-line" style="width:72%"></div></div>'}`.repeat(1)
    + '</div>';
}
function emptyState(icon, title, hint, actionLabel, actionAttr){
  return `<div class="state"><div class="ic">${icon}</div><h4>${esc(title)}</h4>`
    + `<p>${esc(hint)}</p>`
    + (actionLabel ? `<button class="primary" ${actionAttr}>${esc(actionLabel)}</button>` : '')
    + `</div>`;
}
function errorState(e, retryAttr){
  const d = describeError(e);
  return `<div class="state err"><div class="ic">✕</div><h4>${esc(d.title)}</h4>`
    + `<p>${esc(d.hint)}</p>`
    + (retryAttr ? `<button class="primary" ${retryAttr}>Retry</button>` : '')
    + `<pre>${esc(String((e && e.message) || e || ''))}</pre></div>`;
}

/* ---------- data-quality banner ---------- */
function dataQualityBanner(dq){
  if(!dq || !dq.warnings || !dq.warnings.length) return '';
  return `<div class="dq"><div class="ic">!</div><div><h4>This result is incomplete</h4>`
    + `<ul>${dq.warnings.map(w => `<li>${esc(w)}</li>`).join('')}</ul></div></div>`;
}
function reportDataQuality(dq, context){
  if(!dq || dq.complete !== false) return;
  (dq.warnings || []).forEach(w =>
    notify('warn', context + ': incomplete result', w, {duration: 12000}));
}

/* ---------- connection badge ---------- */
function setConn(state, text){
  const el = document.getElementById('conn');
  if(!el) return;
  el.className = 'badge conn' + (state ? ' ' + state : '');
  el.innerHTML = `<span class="dot"></span><span>${esc(text)}</span>`;
}

/* ---------- mobile nav ---------- */
function toggleNav(force){
  const open = force !== undefined ? force : !document.body.classList.contains('nav-open');
  document.body.classList.toggle('nav-open', open);
}

/* ---------- global safety nets ---------- */
window.addEventListener('error', ev => {
  notify('error', 'Unexpected interface error',
    (ev.message || 'Script error') + (ev.lineno ? ' (line ' + ev.lineno + ')' : ''));
});
window.addEventListener('unhandledrejection', ev => {
  const r = ev.reason;
  if(r && r.__uxHandled) return;
  const d = describeError(r);
  notify('error', d.title, d.hint);
});
window.addEventListener('offline', () => {
  document.getElementById('offlineBar')?.classList.add('on');
  setStatus('Browser is offline. Requests will fail until the connection returns.', 'error');
});
window.addEventListener('online', () => {
  document.getElementById('offlineBar')?.classList.remove('on');
  setStatus('Connection restored.', 'success');
});
document.addEventListener('keydown', ev => {
  if(ev.key === 'Escape'){
    document.querySelectorAll('#toasts .toast .x').forEach(b => b.click());
    toggleNav(false);
  }
});

async function api(u){
  uxRequestStart();
  const ctl=new AbortController();
  const to=setTimeout(()=>ctl.abort(),UX_TIMEOUT_MS);
  try{
    const r=await fetch(u,{signal:ctl.signal});
    const t=await r.text();
    let d;
    try{d=JSON.parse(t)}catch{throw new Error('HTTP '+r.status+': '+t.slice(0,300))}
    if(!r.ok)throw new Error('HTTP '+r.status+': '+(d.detail||JSON.stringify(d)));
    return d;
  }finally{
    clearTimeout(to);
    uxRequestEnd();
  }
}

function showPage(id,b){
  document.querySelectorAll('.page').forEach(x=>x.classList.remove('active'));
  const pg=document.getElementById(id); if(pg)pg.classList.add('active');
  document.querySelectorAll('.menu button').forEach(x=>x.classList.remove('active'));
  if(b)b.classList.add('active');
  if(typeof layerControl!=='undefined') layerControl.style.display=(id==='traffic')?'inline-block':'none';
  if(typeof packageControl!=='undefined') packageControl.style.display=(id==='dashboard'||id==='browser'||id==='access'||id==='nat'||id==='traffic')?'inline-block':'none';
}

function goTo(id){
  const b=document.querySelector(`.menu button[data-page="${id}"]`);
  showPage(id,b);
}
async function dashboardRefresh(){
  if(!P.value){
    setStatus('Select a Policy Package on the Dashboard first.','warn');notify('warn','No Policy Package selected','Pick a package in the selector at the top, then run the analysis again.');
    return;
  }
  const btn=document.querySelector('#dashboard button.primary');
  return task('dashboard','Analyzing selected policies',async()=>{
    const completed=[];
    busyStep(0);
    await runAccess();
    busyStep(1);
    await loadPolicyBrowser();
    completed.push('Access');
    busyStep(2);
    await runNat();
    completed.push('NAT');
    busyStep(3);

    // browserData / accessData / natData remain in the browser session, so
    // opening Access Policy, Analyze or NAT Policy immediately shows results.
    showPage('dashboard',document.querySelector('.menu button[data-page="dashboard"]'));
    const msg=completed.join(' + ')+' analysis complete. Results are available in all related pages, including Access Policy.';
    setStatus(msg,'success');
    notify('success','Analysis complete',msg);
    return msg;
  },{
    button:btn,
    sub:'Package: '+P.value+' · elapsed',
    steps:['Analyze Access Control policy','Load configured rulebase','Analyze NAT rulebase','Render dashboard'],
    successMessage:null
  }).catch(()=>{});
}


let pendingAnalysisTab=null;
let pendingNatTab=null;
function drillTo(page,tab=null){
  const b=document.querySelector(`.menu button[data-page="${page}"]`);
  showPage(page,b);
  if(page==='access'){
    pendingAnalysisTab=tab;
    if(accessData){renderAccess(tab||'shadow');pendingAnalysisTab=null;}
  }
  if(page==='nat'){
    pendingNatTab=tab;
    if(natData){renderNat(tab||'rulebase');pendingNatTab=null;}
  }
  if(page==='browser' && typeof browserData!=='undefined' && browserData){
    renderPolicyBrowser(browserData.rules);
  }
}
window.addEventListener('DOMContentLoaded',()=>{
  primeEmptyStates();
  setStatus('Ready. No API calls are made automatically \u2014 pick a Policy Package and run an analysis.','info');
  notify('info','Read-only tool',
    'Firewall Insight only issues show-* Management API calls. It never publishes or installs policy.',
    {duration:7000});
});

function toggleTheme(){document.body.classList.toggle('light');localStorage.setItem('fw-theme',document.body.classList.contains('light')?'light':'dark')}
if(localStorage.getItem('fw-theme')==='light')document.body.classList.add('light');

async function testConn(ev){
  setConn('testing','Testing…');
  return task('conn','Testing Management API',async()=>{
    const d=await api('/api/checkpoint/test');
    setConn('ok','Connected · API '+(d.api_server_version||'?'));
    const m='Connected. Persistent read-only API session is ready.';
    setStatus(m,'success');
    notify('success','Management API reachable','API '+(d.api_server_version||'?')+' · read-only session established.');
    return d;
  },{
    blocking:false,
    button:ev&&ev.currentTarget,
    successMessage:null
  }).catch(()=>{setConn('bad','Connection failed')});
}
async function loadMetadata(force=false,ev){
  return task('meta','Loading policy metadata',async()=>{
    const d=await api('/api/bootstrap?force='+(force?'true':'false'));
    L.innerHTML='<option value="">Select Access Layer...</option>'+d.layers.map(x=>`<option>${esc(x.name)}</option>`).join('');
    P.innerHTML='<option value="">Select Policy Package...</option>'+d.packages.map(x=>`<option>${esc(x.name)}</option>`).join('');
    const m=`Loaded ${d.layers.length} Access Layers and ${d.packages.length} packages`+(d.cached?' (from cache)':'')+'.';
    setStatus(m,'success');
    if(!d.layers.length||!d.packages.length)
      notify('warn','Nothing to select','The Management API returned no '+(!d.packages.length?'policy packages':'access layers')+'. Check that this API user has read permission.');
    else notify('success','Metadata loaded',m);
    return d;
  },{blocking:false,button:ev&&ev.currentTarget,successMessage:null}).catch(()=>{});
}

function isAlertMetric(label){
  return [
    'Shadow / Redundant','Duplicate Groups','Any / Any / Any',
    'Duplicate NAT','Broad Any/Any/Any','Disabled NAT','Possible No-Translation'
  ].includes(String(label||''));
}
function alertValue(label,value){
  const n=Number(value);
  if(isAlertMetric(label) && Number.isFinite(n) && n>0){
    return `<span class="alert-count" title="Finding requires review">${esc(value)}</span>`;
  }
  return esc(value);
}
function setDashboardMetric(el,value,isFinding=false){
  if(!el)return;
  const n=Number(value);
  el.innerHTML=(isFinding && Number.isFinite(n) && n>0)
    ? `<span class="alert-count" title="Finding requires review">${esc(value)}</span>`
    : esc(value);
}
function metricCards(el,items){
  el.classList.remove('hidden');
  el.innerHTML=items.map(x=>`<div class="card"><div class="metric-label">${esc(x[0])}</div><div class="metric">${alertValue(x[0],x[1])}</div></div>`).join('');
}


async function loadPolicyBrowser(){
  if(!P.value){setStatus('Select a Policy Package first.','warn');notify('warn','No Policy Package selected','Choose a package from the selector at the top of the page.');return}
  browserBtn.disabled=true;
  browserBtn.dataset.busy='1';
  setStatus('Loading configured Access Policy without optimizer analysis…','busy');
  browserResults.innerHTML=skeletonTable(13,10);

  try{
    browserData=await api('/api/package-policy-browser?package='+encodeURIComponent(P.value));
    browserCount.textContent=browserData.total_rules+' access rules';
    metricCards(browserSummary,[
      ['Access Rules',browserData.total_rules],
      ['Policy Type','Access Control'],
      ['Top-Level Rules',browserData.top_level_rules],
      ['Inline Rules',browserData.inline_rules],
      ['Inline Layers',browserData.inline_layers],
      ['Policy Package',P.value]
    ]);
    renderPolicyBrowser(browserData.rules);
    renderDataQuality('browserDq',browserData.data_quality);
    reportDataQuality(browserData.data_quality,'Access Policy');
    if(!browserData.total_rules)
      browserResults.innerHTML=emptyState('▤','No rules returned',
        'The package resolved, but its Access layer contained no rules. Confirm in SmartConsole that this package has a policy.',
        'Reload','onclick="loadPolicyBrowser()"');
    setStatus('Policy Browser loaded — '+browserData.total_rules+' top-level + '+browserData.inline_rules+' inline rule(s). No optimizer analysis was performed.','success');
  }catch(e){
    browserResults.innerHTML=errorState(e,'onclick="loadPolicyBrowser()"');
    fail(e,'Access Policy');
    throw e;
  }finally{
    browserBtn.disabled=false;
    delete browserBtn.dataset.busy;
  }
}

function policyActionClass(action){
  const a=String(action||'').toLowerCase();
  if(a.includes('accept'))return 'good';
  if(a.includes('drop')||a.includes('reject'))return 'bad';
  return 'purple';
}


function hierarchyKey(layer,rule){
  return `${String(layer||'')}::${String(rule??'')}`;
}

function accessHierarchyRows(rows){
  const top=[];
  const childMap=new Map();
  const orphans=[];

  for(const r of rows||[]){
    if(Number(r.depth||0)===0){
      top.push(r);
      continue;
    }
    const key=hierarchyKey(r.parent_layer,r.parent_rule);
    if(!r.parent_rule && r.parent_rule!==0){
      orphans.push(r);
      continue;
    }
    if(!childMap.has(key))childMap.set(key,[]);
    childMap.get(key).push(r);
  }

  const output=[];
  for(const parent of top){
    const key=hierarchyKey(parent.layer,parent.rule);
    const children=childMap.get(key)||[];
    output.push({...parent,_row_kind:'parent',_inline_count:children.length});
    for(const child of children){
      output.push({...child,_row_kind:'inline'});
    }
    childMap.delete(key);
  }

  // Preserve data even when a parent cannot be matched.
  for(const children of childMap.values()){
    for(const child of children)orphans.push(child);
  }
  for(const child of orphans){
    output.push({...child,_row_kind:'inline'});
  }
  return output;
}

function renderInlineDashboardSummary(s){
  const box=document.getElementById('inlineAnalysisSummary');
  if(!box)return;
  if(!s || Number(s.inline_layers||0)<=0){
    box.style.display='none';
    return;
  }
  box.style.display='block';
  diLayers.textContent=s.inline_layers||0;
  diRules.textContent=s.inline_rules||0;
  setDashboardMetric(diShadow,s.inline_shadow_findings||0,true);
  setDashboardMetric(diDup,s.inline_duplicate_groups||0,true);
  setDashboardMetric(diAny,s.inline_any_any_any_rules||0,true);
}

function renderPolicyBrowser(rows){
  if(!rows)rows=[];
  rows=accessHierarchyRows(rows);
  browserResults.innerHTML=`
    <div class="section-title">
      <h3>Configured Rulebase</h3>
      <span class="hint">${browserData?.top_level_rules??0} top-level + ${browserData?.inline_rules??0} inline rule(s)</span>
    </div>
    <div class="table-wrap" style="margin-top:12px">
      <table>
        <thead>
          <tr>
            <th>Layer</th><th>Rule</th><th>Section</th><th>Name</th><th>Source</th>
            <th>Destination</th><th>VPN</th><th>Service</th><th>Action</th>
            <th>Track</th><th>Install On</th><th>Hits</th><th>Enabled</th>
          </tr>
        </thead>
        <tbody>
          ${rows.map(r=>`<tr class="${r._row_kind==='inline'?'inline-child-row':(r._inline_count?'inline-parent-row':'')}">
            <td>${r._row_kind==='inline'
              ? `<span class="inline-layer-name"><span class="pill inline">${esc(r.layer||'Inline Layer')}</span></span><br><span class="muted">${esc(r.layer_path||'')}</span>`
              : `<span class="pill good">${esc(r.layer||'Access Layer')}</span><br><span class="muted">${r._inline_count?`${esc(r._inline_count)} inline rule(s) attached`:'Top-level'}</span>`
            }</td>
            <td><span class="rule-no">${r._row_kind==='inline'?'↳ ':''}Rule ${esc(r.display_rule||r.rule)}</span>${r.parent_rule!=null?`<br><span class="muted">under Parent Rule ${esc(r.parent_rule)}</span>`:''}</td>
            <td>${esc(r.section||'—')}</td>
            <td>${esc(r.name||'—')}</td>
            <td>${esc(r.source||'—')}</td>
            <td>${esc(r.destination||'—')}</td>
            <td>${esc(r.vpn||'—')}</td>
            <td>${esc(r.service||'—')}</td>
            <td><span class="pill ${policyActionClass(r.action)}">${esc(r.action||'—')}</span></td>
            <td>${esc(r.track||'—')}</td>
            <td>${esc(r.install_on||'—')}</td>
            <td>${esc(r.hits??'—')}</td>
            <td>${r.enabled?'<span class="pill good">Enabled</span>':'<span class="pill bad">Disabled</span>'}</td>
          </tr>`).join('')}
        </tbody>
      </table>
    </div>`;
}

function filterPolicyBrowser(){
  if(!browserData)return;
  const q=String(policySearch.value||'').trim().toLowerCase();
  const af=String(actionFilter.value||'').toLowerCase();

  const rows=browserData.rules.filter(r=>{
    const text=[
      r.layer,r.layer_path,r.parent_rule,r.rule,r.section,r.name,r.source,r.destination,r.vpn,r.service,
      r.action,r.track,r.install_on,r.comments
    ].join(' ').toLowerCase();

    const qok=!q||text.includes(q);
    const aok=!af||String(r.action||'').toLowerCase().includes(af);
    return qok&&aok;
  });

  renderPolicyBrowser(rows);
}

function exportRawPolicy(){
  if(!P.value){setStatus('Select a Policy Package first.','warn');notify('warn','No Policy Package selected','Choose a package from the selector at the top of the page.');return}
  S.textContent='Package-level CSV export will be added after package/inline validation. The on-screen Access Policy view contains the complete package context.';
}


async function runAccess(){
 if(!P.value){setStatus('Select a Policy Package first.','warn');notify('warn','No Policy Package selected','Choose a package from the selector at the top of the page.');return}
 setStatus('Analyzing Access Policy Package…','busy');
 if(typeof accessCards!=='undefined'&&accessCards&&!accessData) accessCards.innerHTML=skeletonCards(8);
 try{
   accessData=await api('/api/package-analyze?package='+encodeURIComponent(P.value));let s=accessData.summary;
   metricCards(accessCards,[['Access Rules',s.total_rules],['Inline Rules Analyzed',s.inline_rules],['Inline Layers',s.inline_layers],['Total Rules Inspected',s.analyzed_rules],['Shadow / Redundant',s.potential_shadowed_or_redundant],['Duplicate Groups',s.duplicate_groups],['Any / Any / Any',s.any_any_any_rules],['Optimizer Score',s.optimization_score+'%']]);
   setDashboardMetric(dAccess,s.total_rules,false);dAccessDetail.textContent=`SmartConsole: ${s.top_level_rules} parent/top-level rule(s) · ${s.inline_rules} inline rule(s) analyzed`;setDashboardMetric(dShadow,s.potential_shadowed_or_redundant,true);setDashboardMetric(dDup,s.duplicate_groups,true);renderInlineDashboardSummary(s);
   dashLayer.textContent=(accessData?.root_layers||[]).join(', ')||'Resolved from package';
   dashFindings.innerHTML=`<table style="min-width:650px"><thead><tr><th>Finding</th><th>Count</th><th>Meaning</th></tr></thead><tbody>
     <tr class="drill-row" onclick="drillTo('access','shadow')" title="Open Shadow / Redundant findings"><td>Shadow / Redundant</td><td>${s.potential_shadowed_or_redundant?`<span class="alert-count">${esc(s.potential_shadowed_or_redundant)}</span>`:esc(s.potential_shadowed_or_redundant)}</td><td>${esc(s.top_level_shadow_findings||0)} top-level + ${esc(s.inline_shadow_findings||0)} inline finding(s).</td></tr>
     <tr class="drill-row" onclick="drillTo('access','duplicates')" title="Open Duplicate Access findings"><td>Duplicate Access</td><td>${s.duplicate_groups?`<span class="alert-count">${esc(s.duplicate_groups)}</span>`:esc(s.duplicate_groups)}</td><td>${esc(s.top_level_duplicate_groups||0)} top-level + ${esc(s.inline_duplicate_groups||0)} inline group(s).</td></tr>
     <tr class="drill-row" onclick="drillTo('access','any')" title="Open Any / Any / Any findings"><td>Any / Any / Any</td><td>${s.any_any_any_rules?`<span class="alert-count">${esc(s.any_any_any_rules)}</span>`:esc(s.any_any_any_rules)}</td><td>${esc(s.top_level_any_any_any_rules||0)} top-level + ${esc(s.inline_any_any_any_rules||0)} inline rule(s).</td></tr>
     <tr><td>Optimizer Score</td><td>${esc(s.optimization_score)}%</td><td>Heuristic score from this analyzer, not Check Point Security Score.</td></tr>
   </tbody></table>`;
   renderAccess(pendingAnalysisTab||'shadow');pendingAnalysisTab=null;
   renderDataQuality('accessDq',accessData.data_quality);
   reportDataQuality(accessData.data_quality,'Analyze');
   const findings=(s.potential_shadowed_or_redundant||0)+(s.duplicate_groups||0)+(s.any_any_any_rules||0);
   setStatus('Access Policy analysis complete — '+s.analyzed_rules+' rule(s) inspected, '+findings+' finding(s), score '+s.optimization_score+'%.','success');
   if(findings) notify('warn',findings+' optimization finding(s)',
     (s.potential_shadowed_or_redundant||0)+' shadow/redundant · '+(s.duplicate_groups||0)+' duplicate group(s) · '+(s.any_any_any_rules||0)+' Any/Any/Any. Click a dashboard count to drill in.',
     {duration:10000});
   if(s.cleanup_rules) notify('info','Cleanup rules excluded',
     s.cleanup_rules+' trailing Any/Any/Any deny rule(s) were counted as cleanup rules, not findings.');
 }catch(e){
   if(typeof accessFindings!=='undefined'&&accessFindings) accessFindings.innerHTML=errorState(e,'onclick="runAccess()"');
   fail(e,'Analyze');
   throw e;
 }
}
function accessTabs(kind){let d=accessData;return `<div class="tabs"><button class="${kind==='shadow'?'active':''}" onclick="renderAccess('shadow')">Shadow / Redundant</button><button class="${kind==='duplicates'?'active':''}" onclick="renderAccess('duplicates')">Duplicate Rules (${d.findings.duplicates.length})</button><button class="${kind==='any'?'active':''}" onclick="renderAccess('any')">Any Rules (${(d.findings.any_any_any_rules||[]).length})</button></div>`}
function renderAccess(kind){
 if(!accessData)return;let d=accessData,t=accessTabs(kind);
 if(kind==='shadow'){
   let sh=d.findings.shadowing||[];
   accessFindings.innerHTML=t+'<div class="section-title"><h3>Shadow / Redundant Findings</h3><span class="hint">'+sh.length+' finding(s)</span></div>'+
   (sh.length?`<div class="table-wrap"><table><thead><tr><th>Layer</th><th>Rule</th><th>Covered By</th><th>Class</th><th>Action</th><th>Source Match</th><th>Destination Match</th><th>Service Match</th></tr></thead><tbody>${
     sh.map(x=>`<tr><td><span class="pill ${Number(x.depth||0)>0?'purple':'good'}">${esc(x.layer||'')}</span></td><td><span class="rule-no">Rule ${esc(x.display_rule||x.rule)}</span><br><span class="muted">${esc(x.rule_name)}</span></td><td><span class="rule-no">Rule ${esc(x.covered_by)}</span><br><span class="muted">${esc(x.covered_by_name)}</span></td><td><span class="pill ${x.risk==='High'?'bad':'warn'}">${esc(x.classification)} · ${esc(x.risk)}</span></td><td>${esc(x.earlier_action)} → ${esc(x.later_action)}</td><td>${friendly(x.source_reason)}</td><td>${friendly(x.destination_reason)}</td><td>${friendly(x.service_reason)}</td></tr>`).join('')
   }</tbody></table></div>`:'<p>No conservative findings.</p>');
 }else if(kind==='duplicates'){
   let gs=d.findings.duplicates||[];
   accessFindings.innerHTML=t+'<h3>Duplicate Rules</h3>'+(gs.length?gs.map(g=>`<div class="card" style="margin:12px 0"><div class="section-title"><b>Duplicate Group ${esc(g.group)} <span class="pill purple">Exact Duplicate</span></b><span class="hint">${esc(g.recommendation)}</span></div><div class="table-wrap"><table><tr><th>Layer</th><th>Rule</th><th>Name</th><th>Source</th><th>Destination</th><th>Service</th><th>Action</th></tr>${g.members.map(m=>`<tr><td><span class="pill purple">${esc(m.layer||g.layer||'')}</span></td><td><span class="rule-no">Rule ${esc(m.display_rule||m.rule)}</span></td><td>${esc(m.name)}</td><td>${esc(m.source)}</td><td>${esc(m.destination)}</td><td>${esc(m.service)}</td><td>${esc(m.action)}</td></tr>`).join('')}</table></div></div>`).join(''):'<p>No exact duplicate groups found.</p>');
 }else{
   let rs=d.findings.any_any_any_rules||[];
   accessFindings.innerHTML=t+'<h3>Any / Any / Any Rules</h3>'+(rs.length?`<div class="table-wrap"><table><tr><th>Layer</th><th>Rule</th><th>Name</th><th>Source</th><th>Destination</th><th>Service</th><th>Action</th><th>Hits</th></tr>${rs.map(r=>`<tr><td><span class="pill ${Number(r.depth||0)>0?'purple':'good'}">${esc(r.layer||'')}</span></td><td><span class="rule-no">Rule ${esc(r.display_rule||r.rule)}</span></td><td>${esc(r.name)}</td><td>${esc(r.source)}</td><td>${esc(r.destination)}</td><td>${esc(r.service)}</td><td>${esc(r.action)}</td><td>${esc(r.hits??'N/A')}</td></tr>`).join('')}</table></div>`:'<p>No Any / Any / Any rules found.</p>')+cleanupNote(d);
 }
}
function cleanupNote(d){
  let cs=(d.findings&&d.findings.cleanup_rules)||[];
  if(!cs.length)return '';
  return `<p class="muted" style="margin-top:14px">Excluded ${cs.length} cleanup rule(s) — `
    +cs.map(c=>`${esc(c.layer||'')} Rule ${esc(c.display_rule||c.rule)} (${esc(c.action||'')})`).join(', ')
    +`. A trailing Any/Any/Any deny rule is expected in every policy and is not an optimization finding.</p>`;
}
function friendly(v){v=String(v||'');return esc(v.replace('Exact object/group UID coverage','Exact Match').replace('Subnet/range coverage','Network Contains').replace('Protocol/port coverage','Port / Service Contains').replace(/^Any$/,'Covered by Any'))}

async function runNat(){
 if(!P.value){setStatus('Select a Policy Package first.','warn');notify('warn','No Policy Package selected','Choose a package from the selector at the top of the page.');return}
 setStatus('Loading and analyzing NAT rulebase…','busy');
 try{
   natData=await api('/api/nat-analyze?package='+encodeURIComponent(P.value)); renderNatSpecialViews(natData);let s=natData.summary;
   metricCards(natCards,[['Total NAT Rules',s.total_nat_rules],['Duplicate NAT',s.duplicate_nat_groups],['Broad Any/Any/Any',s.broad_original_any_any_any],['Disabled NAT',s.disabled_nat_rules],['Possible No-Translation',s.possible_no_translation_rules]]);
   setDashboardMetric(dNat,s.total_nat_rules,false);setDashboardMetric(dNatDup,s.duplicate_nat_groups,true);dashPackage.textContent=P.value||'Not selected';natTabs.style.display='flex';renderNat(pendingNatTab||'rulebase');pendingNatTab=null;
   const hits=s.nat_hits_available;
   setStatus('NAT analysis complete — '+s.total_nat_rules+' rule(s). Hit counts '+(hits?'available':'not supported by this Management API build')+'.',hits?'success':'warn');
   if(!hits) notify('info','NAT hit counts unavailable',
     'This Management API build rejected show-hits on show-nat-rulebase, so the Hits column stays empty. Access hit counts are unaffected.',
     {duration:9000});
 }catch(e){
   fail(e,'NAT Policy');
   throw e;
 }
}
function renderNat(kind,b){
 document.querySelectorAll('#natTabs button').forEach(x=>x.classList.remove('active'));if(b)b.classList.add('active');
 if(!natData)return;
 if(kind==='rulebase'){
   let rs=natData.rules||[];
   natResults.innerHTML='<h3>NAT Rulebase</h3>'+natTable(rs);
 }else if(kind==='duplicates'){
   let gs=natData.findings.duplicates||[];
   natResults.innerHTML='<h3>Duplicate NAT Rules</h3>'+(gs.length?gs.map(g=>`<div class="card" style="margin:12px 0"><div class="section-title"><b>Duplicate NAT Group ${esc(g.group)} <span class="pill purple">Exact NAT Duplicate</span></b><span class="hint">${esc(g.recommendation)}</span></div>${natTable(g.members)}</div>`).join(''):'<p>No exact duplicate NAT groups found.</p>');
 }else{
   let nums=new Set(natData.findings.broad_rule_numbers||[]),rs=natData.rules.filter(r=>nums.has(r.rule));
   natResults.innerHTML='<h3>Broad Original Any / Any / Any NAT Rules</h3>'+(rs.length?natTable(rs):'<p>No broad NAT rules found.</p>');
 }
}
function natTable(rs){return `<div class="table-wrap"><table><thead><tr><th>Rule</th><th>Name</th><th>Original Source</th><th>Original Destination</th><th>Original Service</th><th>Translated Source</th><th>Translated Destination</th><th>Translated Service</th><th>Install On</th><th>Method</th><th>Hits</th></tr></thead><tbody>${rs.map(r=>`<tr><td><span class="rule-no">Rule ${esc(r.display_rule||r.rule)}</span></td><td>${esc(r.name)}</td><td>${esc(r.original_source)}</td><td>${esc(r.original_destination)}</td><td>${esc(r.original_service)}</td><td>${esc(r.translated_source)}</td><td>${esc(r.translated_destination)}</td><td>${esc(r.translated_service)}</td><td>${esc(r.install_on)}</td><td>${esc(r.method)}</td><td>${esc(r.hits??'N/A')}</td></tr>`).join('')}</tbody></table></div>`}

async function trace(){
 if(!L.value){setStatus('Select an Access Layer first.','warn');notify('warn','No Access Layer selected','Traffic Path needs an Access Layer so it knows which rulebase to start from.');return}
 if(!src.value||!dst.value||port.value.trim()===''){setStatus('Enter Source, Destination and Port/Service.','warn');notify('warn','Missing input','Traffic Path needs a source, a destination and a port or service name. Source and destination accept an IP or an FQDN.');return}
 let q=new URLSearchParams({layer:L.value,src:src.value.trim(),dst:dst.value.trim(),protocol:proto.value,service:port.value.trim()});if(P.value)q.set('package',P.value);
 const traceBtn=document.querySelector('#traffic button.primary');
 if(traceBtn){traceBtn.dataset.busy='1';traceBtn.disabled=true}
 setStatus('Analyzing traffic path through Access and Inline Layers…','busy');
 busyShow('Tracing traffic path',
   src.value.trim()+' \u2192 '+dst.value.trim()+' \u00b7 elapsed',
   ['Load package / inline layer tree','Resolve objects and service','Walk the ordered rulebase','Correlate NAT']);
 try{
   let d=await api('/api/traffic-path?'+q),w=d.access.winner,n=d.nat||[],path=d.access.path||[],possible=d.access.possible_winner;
   const confidence=d.access.confidence||'none';
   const actionClass=String(w?.action||'').toLowerCase().includes('accept')?'good':(String(w?.action||'').toLowerCase().includes('drop')||String(w?.action||'').toLowerCase().includes('reject')?'bad':'purple');

   const pathHtml=path.length?`
     <div class="card" style="margin-top:16px">
       <div class="section-title"><h3>Matched Policy Path</h3><span class="hint">Top-level → Inline Layer → Final Action</span></div>
       <div class="table-wrap" style="margin-top:12px">
         <table>
           <thead><tr><th>Step</th><th>Rule</th><th>Layer</th><th>Name</th><th>Action</th><th>Transition</th><th>Match Details</th></tr></thead>
           <tbody>${path.map((x,i)=>`<tr>
             <td>${i+1}</td>
             <td><span class="rule-no">Rule ${esc(x.display_rule||x.rule)}</span></td>
             <td><span class="pill ${Number(x.depth||0)>0?'inline':'good'}">${esc(x.layer||'—')}</span></td>
             <td>${esc(x.name||'—')}</td>
             <td><span class="pill ${String(x.action||'').toLowerCase().includes('accept')?'good':(String(x.action||'').toLowerCase().includes('drop')?'bad':'purple')}">${esc(x.action||'Inline')}</span></td>
             <td>${x.transition==='inline-layer'?`→ Inline Layer: <b>${esc(x.inline_layer||'')}</b>`:'Final rule'}</td>
             <td>Src: ${esc(x.source_match||'—')}<br>Dst: ${esc(x.destination_match||'—')}<br>Svc: ${esc(x.service_match||'—')}</td>
           </tr>`).join('')}</tbody>
         </table>
       </div>
     </div>`:'';

   traceResult.innerHTML=`<div class="flow">
     <div class="step"><span class="muted">Source</span><br><b>${esc(d.query.source)}</b></div>
     <div class="arrow">→</div>
     <div class="step"><span class="muted">${w?'Matched Access Rule':(possible?'Possible Earlier Rule':'Matched Access Rule')}</span><br>${w?`<b>Rule ${esc(w.display_rule||w.rule)}</b><br>${esc(w.name)}<br><span class="muted">${esc(w.layer||'')}</span>`:(possible?`<b>Rule ${esc(possible.display_rule||possible.rule)}</b><br>${esc(possible.name||'')}<br><span class="muted">Requires gateway context</span>`:'No matching rule')}</div>
     <div class="arrow">→</div>
     <div class="step"><span class="muted">Final Action</span><br><span class="pill ${confidence==='unknown'?'warn':actionClass}">${esc(w?.action||(confidence==='unknown'?'UNVERIFIED':'NO MATCH'))}</span><br><span class="muted">${esc(confidence.toUpperCase())}</span></div>
     <div class="arrow">→</div>
     <div class="step"><span class="muted">Destination</span><br><b>${esc(d.query.destination)}</b><br><span class="muted">${esc(d.query.service_display||((d.query.protocol||'').toUpperCase()+'/'+d.query.port))}</span></div>
   </div>
   <div class="table-wrap" style="margin-top:18px"><table>
     <tr><th>Item</th><th>Result</th><th>Details</th></tr>
     <tr><td>Source</td><td>${esc(d.query.source)}</td><td>${esc(w?.source_match||'—')}</td></tr>
     <tr><td>Destination</td><td>${esc(d.query.destination)}</td><td>${esc(w?.destination_match||'—')}</td></tr>
     <tr><td>Service</td><td>${esc(d.query.service_display||d.query.service_input||'—')}</td><td>${esc(w?.service_match||'—')} · resolved by ${esc(d.query.service_resolved_by||'—')}</td></tr>
     <tr><td>Access Rule</td><td>${w?'Rule '+esc(w.display_rule||w.rule):'No match'}</td><td>${w?`${esc(w.layer||'—')} · ${esc(w.name||'—')}`:esc(d.access.reason||'—')}</td></tr>
     <tr><td>Action</td><td>${esc(w?.action||(confidence==='unknown'?'UNVERIFIED':'—'))}</td><td>${esc(d.access.reason||'—')} · Confidence: ${esc(confidence)}</td></tr>
     <tr><td>NAT</td><td>${n.length?'Rule '+esc(n[0].rule):(P.value?'No match':'Not checked')}</td><td>${n.length?`Source → ${esc(n[0].translated_source)} · Destination → ${esc(n[0].translated_destination)}`:'—'}</td></tr>
   </table></div>
   ${pathHtml}
   <div class="hint" style="margin-top:12px">${(d.limitations||[]).map(esc).join(' · ')}</div>`;
   reportDataQuality(d.data_quality,'Traffic Path');
   if(d.nat_error) notify('warn','NAT correlation failed',d.nat_error+' The Access result above is unaffected.');
   if(d.access.matched){
     const msg=`Traffic path matched configured policy path (${confidence}).`;
     setStatus(msg,confidence==='exact'?'success':'warn');
     if(confidence==='exact')
       notify('success','Matched: '+String(w.action||''),
         'Rule '+(w.display_rule||w.rule)+' in '+(w.layer||'')+' \u2014 every condition was verified against the configuration.');
     else
       notify('warn','Matched, but inferred',
         'Rule '+(w.display_rule||w.rule)+' matched, however an earlier rule contains conditions this static simulator cannot evaluate. Treat the gateway log as authoritative.',
         {duration:12000});
   }else if(confidence==='unknown'){
     setStatus('Traffic path is unverified because an earlier rule requires gateway context.','warn');
     notify('warn','UNVERIFIED \u2014 deliberately not guessing',
       (d.access.reason||'An earlier rule could not be evaluated statically.')+' Reporting a confident answer here would risk being confidently wrong.',
       {duration:0});
   }else{
     setStatus('Traffic path analysis complete: no final matching rule found.','info');
     notify('info','No matching rule','No rule in the selected layer matched this flow.');
   }
 }catch(e){
   traceResult.innerHTML=errorState(e,'onclick="trace()"');
   fail(e,'Traffic Path');
 }finally{
   busyHide();
   if(traceBtn){delete traceBtn.dataset.busy;traceBtn.disabled=false}
 }
}

async function loadMap(ev){
  return task('map','Loading gateway topology',async()=>{
    mapData=await api('/api/network-map?force=true');
    inventory.innerHTML=mapData.nodes.map(n=>`<div class="node"><b>${esc(n.name)}</b><br><span class="muted">${esc(n.role||n.type)}</span><br>${esc(n.cidr||(n.ips||[]).join(', '))}</div>`).join('');
    renderTopology(mapData);
    mapNote.textContent=(mapData.limitations||[]).join(' · ');
    mapMode('topology');
    const m=`Loaded ${mapData.count} nodes and ${mapData.edges.length} relationships.`;
    setStatus(m,'success');
    if(!mapData.count) notify('warn','No topology objects',
      'show-gateways-and-servers returned nothing. Check that this API user can read gateway objects.');
    else notify('success','Topology loaded',m);
    return mapData;
  },{
    button:ev&&ev.currentTarget,
    sub:'Reading gateways and servers · elapsed',
    steps:['Fetch gateways and servers','Derive interfaces and subnets','Render graph'],
    successMessage:null
  }).catch(()=>{});
}
function mapMode(v){topology.classList.toggle('hidden',v!=='topology');inventory.classList.toggle('hidden',v!=='inventory')}

function topoIcon(role){
  if(role==='gateway'){
    return `<g transform="translate(10,11)">
      <rect x="0" y="2" width="27" height="19" rx="3" fill="none" stroke="#d8c6ff" stroke-width="1.5"/>
      <path d="M0 9h27M0 15h27M8 2v7M18 2v7M5 9v6M15 9v6M23 9v6" stroke="#d8c6ff" stroke-width="1.2"/>
      <path d="M31 5l7 3v6c0 5-3 8-7 10-4-2-7-5-7-10V8z" fill="#8b5cf6" stroke="#cbb7ff" stroke-width="1"/>
    </g>`;
  }
  if(role==='management'){
    return `<g transform="translate(10,10)">
      <rect x="0" y="0" width="31" height="23" rx="3" fill="none" stroke="#7ce8b7" stroke-width="1.5"/>
      <path d="M5 7h15M5 15h15" stroke="#7ce8b7" stroke-width="1.3"/>
      <circle cx="25" cy="7" r="2" fill="#38d996"/>
      <circle cx="25" cy="15" r="2" fill="#38d996"/>
      <path d="M7 23v4M24 23v4" stroke="#7ce8b7" stroke-width="1.3"/>
    </g>`;
  }
  return '';
}
function renderTopology(d){
 let ns=d.nodes||[],es=d.edges||[],pos={},dev=ns.filter(n=>['gateway','management','device'].includes(n.role)),ifs=ns.filter(n=>n.role==='interface'),nets=ns.filter(n=>n.role==='network');
 dev.forEach((n,i)=>pos[n.id]={x:70,y:80+i*170});
 ifs.forEach(n=>{let sib=ifs.filter(x=>x.parent===n.parent),idx=sib.findIndex(x=>x.id===n.id),p=pos[n.parent]||{x:70,y:80};pos[n.id]={x:430,y:p.y+(idx-(sib.length-1)/2)*90}});
 nets.forEach((n,i)=>{let e=es.find(e=>e.to===n.id),p=e?pos[e.from]:null;pos[n.id]={x:810,y:p?p.y:80+i*90}});
 let H=Math.max(590,dev.length*180,ifs.length*90+120),W=1250;
 let edge=es.map(e=>{let a=pos[e.from],b=pos[e.to];if(!a||!b)return'';let x1=a.x+200,y1=a.y+33,x2=b.x,y2=b.y+33,m=(x1+x2)/2;return `<path class="edge" d="M${x1},${y1} C${m},${y1} ${m},${y2} ${x2},${y2}"/><text class="edge-label" x="${m-36}" y="${(y1+y2)/2-5}">${esc(e.label)}</text>`}).join('');
 let nodes=ns.map(n=>{let p=pos[n.id];if(!p)return'';let sub=n.role==='interface'?(n.cidr||''):(n.ips||[]).join(', ');let icon=(n.role==='gateway'||n.role==='management')?topoIcon(n.role):'';let tx=icon?52:12;return `<g class="toponode ${esc(n.role||'device')}" transform="translate(${p.x},${p.y})"><rect width="200" height="66" rx="10"/>${icon}<text x="${tx}" y="27">${esc(n.name).slice(0,24)}</text><text class="sub" x="${tx}" y="47">${esc(sub).slice(0,27)}</text></g>`}).join('');
 topology.innerHTML=`<svg viewBox="0 0 ${W} ${H}" id="topoSvg"><g id="world">${edge}${nodes}</g></svg>`;panZoom();
}
function panZoom(){let svg=topoSvg,w=world,scale=1,tx=0,ty=0,drag=false,lx=0,ly=0;function a(){w.setAttribute('transform',`translate(${tx} ${ty}) scale(${scale})`)}svg.addEventListener('wheel',e=>{e.preventDefault();scale=Math.max(.45,Math.min(2.7,scale*(e.deltaY<0?1.1:.9)));a()},{passive:false});svg.addEventListener('mousedown',e=>{drag=true;lx=e.clientX;ly=e.clientY});window.addEventListener('mouseup',()=>drag=false);svg.addEventListener('mousemove',e=>{if(!drag)return;tx+=(e.clientX-lx)/scale;ty+=(e.clientY-ly)/scale;lx=e.clientX;ly=e.clientY;a()})}
function exportAccess(){if(!L.value){notify('warn','No Access Layer selected','Pick an Access Layer before exporting.');return}location.href='/api/export.csv?layer='+encodeURIComponent(L.value)}

function showAccessTab(tab,btn){
  ['all','shadow','duplicates','any'].forEach(x=>{
    const el=document.getElementById('access-'+x+'-view');
    if(el) el.style.display=(x===tab)?'block':'none';
  });
  document.querySelectorAll('#access-tabs button').forEach(b=>b.classList.remove('active'));
  if(btn) btn.classList.add('active');
}

function renderAccessAll(data){
  const body=document.getElementById('access-all-body');
  if(!body) return;
  const rules=(data && (data.rules || data.rulebase || data.all_rules)) || [];
  if(!rules.length){
    body.innerHTML='<tr><td colspan="13" class="muted">No rule rows returned.</td></tr>';
    return;
  }
  const desc=(v)=>{
    if(v==null) return '—';
    if(Array.isArray(v)) return v.map(desc).join(', ');
    if(typeof v==='object') return v.name || v.uid || '—';
    return String(v);
  };
  body.innerHTML=rules.map((r,i)=>`<tr>
    <td><strong>Rule ${esc(r.rule_number ?? r.rule ?? (i+1))}</strong></td>
    <td>${esc(r.name||'—')}</td>
    <td>${esc(desc(r.source))}</td>
    <td>${esc(desc(r.destination))}</td>
    <td>${esc(desc(r.service))}</td>
    <td>${esc(desc(r.action))}</td>
    <td>${esc(desc(r.track))}</td>
    <td>${r.enabled===false?'Disabled':'Enabled'}</td>
  </tr>`).join('');
}

function renderNatSpecialViews(data){
  const rules=(data && data.rules)||[];
  const findings=(data && data.findings)||{};

  const norm=v=>String(v??'').trim();
  const disabledNums=new Set((findings.disabled_rule_numbers||[]).map(norm));
  const noTransNums=new Set((findings.possible_no_translation_rule_numbers||[]).map(norm));

  const disabled=rules.filter(r=>disabledNums.has(norm(r.rule)));
  const noTrans=rules.filter(r=>noTransNums.has(norm(r.rule)));

  const db=document.getElementById('nat-disabled-body');
  if(db){
    db.innerHTML=disabled.length?disabled.map(r=>`<tr>
      <td><strong>Rule ${esc(r.rule)}</strong></td>
      <td>${esc(r.name||'—')}</td>
      <td>${esc(r.original_source)}</td>
      <td>${esc(r.original_destination)}</td>
      <td>${esc(r.original_service)}</td>
      <td>${esc(r.method)}</td>
    </tr>`).join(''):'<tr><td colspan="6" class="muted">No disabled NAT rules found.</td></tr>';
  }

  const nb=document.getElementById('nat-notrans-body');
  if(nb){
    nb.innerHTML=noTrans.length?noTrans.map(r=>`<tr>
      <td><strong>Rule ${esc(r.rule)}</strong></td>
      <td>${esc(r.name||'—')}</td>
      <td>${esc(r.original_source)}</td>
      <td>${esc(r.original_destination)}</td>
      <td>${esc(r.original_service)}</td>
      <td>${esc(r.translated_source)}</td>
      <td>${esc(r.translated_destination)}</td>
      <td>${esc(r.translated_service)}</td>
    </tr>`).join(''):'<tr><td colspan="13" class="muted">No possible no-translation NAT rules found.</td></tr>';
  }

  const dc=document.getElementById('nat-disabled-tab-count');
  if(dc)dc.textContent=`(${disabled.length})`;
  const nc=document.getElementById('nat-notrans-tab-count');
  if(nc)nc.textContent=`(${noTrans.length})`;
}

// Extend the existing NAT tab switcher without changing the current rulebase/duplicate/broad behavior.


function showNatTab(tab,btn){
  // Hide every NAT content area first.
  const ids=['nat-disabled-view','nat-notrans-view'];
  ids.forEach(id=>{const el=document.getElementById(id);if(el)el.style.display='none';});

  // renderNat() owns rulebase / duplicates / broad views.
  // Clear its container when entering the custom views.
  if(tab==='disabled' || tab==='notrans'){
    if(typeof natResults!=='undefined' && natResults) natResults.innerHTML='';

    const target=document.getElementById(tab==='disabled'?'nat-disabled-view':'nat-notrans-view');
    if(target) target.style.display='block';

    if(btn && btn.parentElement){
      btn.parentElement.querySelectorAll('button').forEach(b=>b.classList.remove('active'));
      btn.classList.add('active');
    }
    return;
  }

  // For standard tabs, hide special views and delegate to the original renderer.
  renderNat(tab,btn);
}

</script>
</body>
</html>"""
