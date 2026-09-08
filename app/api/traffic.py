"""Traffic Path: configuration-based simulation of the matched policy path."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from ..path_map import trace_overlay
from ..policy import access_tree, data_quality, package_access_tree
from ..progress import progress_done, progress_set
from ..runtime import cache_get, cache_set, use_client
from ..topology_map import network_map
from ..traffic import correlate_nat, resolve_service_query, trace_access_tree

router = APIRouter()


@router.get("/api/traffic-path")
async def traffic_path(
    layer: str = Query(...),
    src: str = Query(...),
    dst: str = Query(...),
    protocol: str = Query("tcp"),
    service: str | None = Query(None),
    port: int | None = Query(None, ge=0, le=65535),
    package: str | None = Query(None),
    rid: str | None = Query(None),
):
    async def run(c):
        STEPS = 5
        progress_set(rid, 0, "Loading package / inline layer tree", STEPS)
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

        progress_set(rid, 2, "Walking the ordered rulebase", STEPS)
        access = trace_access_tree(
            tree,
            src,
            dst,
            protocol,
            service_query,
            selected_root=layer,
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

        progress_done(rid, "Trace complete")
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
                "The trace now follows configured Inline Layers and Access Sections.",
                "Identity Awareness, dynamic objects, time objects, implied rules, live gateway state, routing and kernel behavior can still make a live log differ.",
                "A rule scoped to a VPN community is reported as unknown, not as a match: whether a flow arrives through that community is live connection state, not configuration.",
                "NAT correlation is configuration-based and does not emulate the live routing/kernel path.",
                "NAT correlation is tri-state: a NAT rule built on an object with no static model is reported as unverified, never as a non-match.",
                "NAT correlation matches original-source and original-destination only; original-service is not evaluated, so a service-specific NAT rule can be reported when it would not fire.",
                "The network map overlay places the endpoints by subnet containment and reports policy certainty and topology certainty separately; it is not a route."
            ]
        }
    return await use_client(run)
