"""Traffic Path: configuration-based simulation of the matched policy path."""

from __future__ import annotations

import asyncio
import socket
from ipaddress import ip_address

from fastapi import APIRouter, HTTPException, Query, BackgroundTasks
import uuid

from ..path_map import trace_overlay
from ..policy import access_tree, data_quality, package_access_tree
from ..progress import progress_done, progress_set
from ..runtime import cache_get, cache_set, use_client
from ..topology_map import network_map
from ..matching import dns_cache_put
from ..traffic import correlate_nat, resolve_service_query, trace_access_tree
from ..implied import build_context

router = APIRouter()


async def _prewarm_dns(*endpoints: str) -> None:
    # ... (same as original)
    loop = asyncio.get_running_loop()
    for raw in endpoints:
        value = str(raw or "").strip()
        if not value:
            continue
        try:
            ip_address(value)
            continue
        except ValueError:
            pass
        try:
            infos = await loop.getaddrinfo(value, None, type=socket.SOCK_STREAM)
        except OSError as exc:
            dns_cache_put(value, [], str(exc))
            continue
        ips: list[str] = []
        for info in infos:
            addr = info[4][0]
            if addr not in ips:
                ips.append(addr)
        dns_cache_put(value, ips, None)


@router.get("/api/ask")
async def ask(background_tasks: BackgroundTasks,
              q: str = Query(..., min_length=3, max_length=500),
              package: str = Query(...), rid: str | None = Query(None)):
    rid = rid or f"auto-{uuid.uuid4().hex}"
    from .. import ask as asker

    async def background_run():
        try:
            async def run(c):
                tree = await package_access_tree(c, package, hydrate=True, rid=rid)
                objects = {}
                for node in tree.get("layers", []):
                    for obj in node.get("payload", {}).get("objects-dictionary", []) or []:
                        if isinstance(obj, dict) and obj.get("uid"):
                            objects[obj["uid"]] = obj
                parsed = asker.parse(q, objects)
                if not parsed["ready"]:
                    res = {"question": q, "parsed": parsed, "ran": False,
                           "answer": asker.clarification(parsed)}
                    progress_done(rid, "Ask complete", result=res)
                    return
                layer = (tree.get("root_layers") or [None])[0] or tree["layers"][0]["name"]
                result = await run_trace(
                    c, layer=layer, src=parsed["source"]["value"],
                    dst=parsed["destination"]["value"], protocol=parsed["service"]["protocol"],
                    service_input=parsed["service"]["input"], package=package, rid=rid)
                res = {"question": q, "parsed": parsed, "ran": True,
                       **asker.explain(result, parsed), "trace": result}
                progress_done(rid, "Ask complete", result=res)
            await use_client(run)
        except Exception as e:
            progress_done(rid, "Error running ask", error=getattr(e, "detail", str(e)))

    background_tasks.add_task(background_run)
    return {"background": True, "rid": rid, "message": "Ask task started in background"}


@router.get("/api/traffic-path")
async def traffic_path(
    background_tasks: BackgroundTasks,
    layer: str = Query(...),
    src: str = Query(...),
    dst: str = Query(...),
    protocol: str = Query("tcp"),
    service: str | None = Query(None),
    port: int | None = Query(None, ge=0, le=65535),
    package: str | None = Query(None),
    rid: str | None = Query(None),
):
    rid = rid or f"auto-{uuid.uuid4().hex}"
    service_input = str(
        service if service not in (None, "")
        else port if port is not None
        else ""
    ).strip()
    if not service_input:
        raise HTTPException(status_code=400, detail="Enter a Port or Service name.")
    
    async def background_run():
        try:
            async def run(c):
                res = await run_trace(
                    c, layer=layer, src=src, dst=dst, protocol=protocol,
                    service_input=service_input, package=package, rid=rid)
                progress_done(rid, "Trace complete", result=res)
            await use_client(run)
        except Exception as e:
            progress_done(rid, "Error running trace", error=getattr(e, "detail", str(e)))
            
    background_tasks.add_task(background_run)
    return {"background": True, "rid": rid, "message": "Traffic trace started in background"}


async def implied_context(c):
    """
    What the tracer needs to know about implied rules, read once per session.

    Both reads are show- commands. A failure of either is kept as a failure:
    the context then says implied rules are unread and no trace is reported as
    definite. It is cached like the network map, including a failed read, so a
    server that refuses the command is not asked again on every trace.
    """
    ctx = cache_get("implied-context")
    if ctx is not None:
        return ctx
    properties = gateways = None
    try:
        properties = await c.show_global_properties()
    except Exception:                                          # noqa: BLE001
        properties = None
    try:
        gateways = await c.show_gateways_and_servers()
    except Exception:                                          # noqa: BLE001
        gateways = None
    ctx = build_context(properties, gateways)
    cache_set("implied-context", ctx)
    return ctx


async def run_trace(c, *, layer: str, src: str, dst: str, protocol: str,
                    service_input: str, package: str | None, rid: str | None):
    """The trace itself, shared by /api/traffic-path and /api/ask.

    One implementation, so a question asked in words gets the same verdict,
    the same UNVERIFIED and the same limitations as the form - not a second
    matcher that could drift from the first.
    """
    STEPS = 5
    progress_set(rid, 0, "Loading package / inline layer tree", STEPS)
    # Load the complete package tree when a Policy Package is selected.
    # This is required to follow Parent Rule -> Inline Layer -> child rule.
    if package:
        tree = await package_access_tree(c, package, hydrate=True, rid=rid)
    else:
        tree = await access_tree(c, layer, hydrate=True)

    progress_set(rid, 1, "Resolving objects and service", STEPS)

    # Build a global resolver from all layer dictionaries so custom
    # service objects can be resolved regardless of which layer uses them.
    from ..resolver import ObjectResolver
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

    # v4.43: when the package is installed on exactly one gateway or cluster,
    # Install On can be decided for it. Otherwise the target stays unknown.
    target = None
    if package:
        try:
            pk = await c.show_package(package)
            tg = pk.get("installation-targets") if isinstance(pk, dict) else None
            if isinstance(tg, list) and len(tg) == 1 and isinstance(tg[0], dict):
                from ..envelope import make_target
                target = make_target(tg[0].get("uid", ""), tg[0].get("name", ""))
        except Exception:                                      # noqa: BLE001
            target = None

    progress_set(rid, 2, "Walking the ordered rulebase", STEPS)
    await _prewarm_dns(src, dst)
    access = trace_access_tree(
        tree,
        src,
        dst,
        protocol,
        service_query,
        selected_root=layer,
        implied=await implied_context(c),
        target=target,
    )

    progress_set(rid, 3, "Correlating NAT", STEPS)
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

    progress_set(rid, 4, "Placing the path on the network map", STEPS)
    # The overlay is a convenience, not the answer. A failure here must not
    # take the trace down with it, so it is reported next to the result
    # instead of raising - the Access verdict above is unaffected.
    map_path, map_path_error = None, None
    try:
        network = cache_get("network-map")
        if network is None:
            network = network_map(await c.show_gateways_and_servers())
            cache_set("network-map", network)
        map_path = trace_overlay(network, src, dst, access)
    except Exception as exc:                                  # noqa: BLE001
        map_path_error = str(exc)

    return {
        "query": {
            "source": src,
            "destination": dst,
            "protocol": service_query.get("protocol", protocol.lower()),
            "port": service_query.get("port"),
            "service_input": service_input,
            "service_display": service_query.get("display"),
            "service_resolved_by": service_query.get("resolved_by"),
            "service_warnings": service_query.get("warnings") or [],
            "layer": layer,
            "package": package,
        },
        "access": access,
        "map_path": map_path,
        "map_path_error": map_path_error,
        "nat": nat,
        "nat_error": nat_error,
        "data_quality": data_quality(c, tree),
        "limitations": [
            "This is a configuration-based Access Control simulation.",
            "A hostname endpoint is resolved by the machine running this "
            "application, not by the gateway. A name that does not resolve "
            "here is reported as unknown rather than as a non-match, "
            "because whether it falls inside an object cannot be decided "
            "without an address - and split-horizon DNS can make the "
            "gateway's answer differ from this one.",
            "The trace now follows configured Inline Layers and Access Sections.",
            "Identity Awareness, dynamic objects, time objects, live gateway state, routing and kernel behavior can still make a live log differ.",
            "Implied rules are not in the rulebase the API returns. Global Properties and the gateway list are read to decide whether one could apply; when one could, or when they cannot be read, the result is not reported as definite.",
            "A service that also restricts source port, protocol signature or ICMP code is reported as unknown when its port matches, because the rule is narrower than its port.",
            "A rule scoped to a VPN community is reported as unknown, not as a match: whether a flow arrives through that community is live connection state, not configuration.",
            "NAT correlation is configuration-based and does not emulate the live routing/kernel path.",
            "NAT correlation is tri-state: a NAT rule built on an object with no static model is reported as unverified, never as a non-match.",
            "NAT correlation matches original-source and original-destination only; original-service is not evaluated, so a service-specific NAT rule can be reported when it would not fire.",
            "The network map overlay places the endpoints by subnet containment and reports policy certainty and topology certainty separately; it is not a route."
        ]
    }

