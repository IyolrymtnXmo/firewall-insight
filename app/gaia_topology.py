"""
Turn Gaia routing data into map nodes, without pretending to know its shape.

The map has always been honest about one thing above all: it draws what an API
field said, and where a relationship is not in the payload it is not drawn.
Routing arrives from a second API whose envelopes differ between Gaia versions,
and this application has no lab-verified sample of every one of them.

So nothing here is written against a shape assumed from documentation. The
readers try the plausible keys, and anything they cannot understand goes into
`unparsed` with the raw entry attached, gets counted, and is reported on the
map's own `limitations` list. A routing map that silently drops the four routes
it could not read is worse than one that says it read six of ten - the first
looks complete.

`tools/probe_gaia.py` records what a real gateway answers so these readers can
be narrowed to the truth rather than widened to every guess.
"""

from __future__ import annotations

from ipaddress import ip_network
from typing import Any

# Envelopes seen across Gaia builds and in the API reference. Ordered by how
# specific they are, so a payload carrying two of them resolves predictably.
LIST_KEYS = ("objects", "routes", "result", "static-routes", "items", "data")

DEST_KEYS = ("destination", "address", "network", "prefix", "dest", "target")
MASK_KEYS = ("mask-length", "mask_length", "prefix-length", "masklen", "subnet-mask")
# `protocol` first: on show-routes it is the routing protocol (Static /
# Connected), which is what a reader wants. `type` is last because on
# show-static-routes it means "the next hop is a gateway" - a statement about
# the hop, not about how the route was learned. Reading it as the protocol is
# how "Static" was displayed as "gateway" in the first live run.
TYPE_KEYS = ("protocol", "route-type", "origin", "type")
INTERFACE_KEYS = ("interface", "device", "dev", "egress-interface")

# Values `type` takes on show-static-routes. They describe the NEXT HOP, not
# how the route was learned, so they must not be reported as the protocol -
# that is how "Static" was displayed as "gateway" in the first live run.
HOP_DESCRIPTORS = {"gateway", "reject", "blackhole", "interface", "local"}

# Drawn on no map, and never dropped in silence: the loopback prefix is on
# every gateway and says nothing about the estate.
SKIP_PREFIXES = ("127.0.0.0/8", "::1/128")


def _rows(payload: Any) -> list[dict[str, Any]]:
    """The list of route objects, whichever envelope this build wrapped it in."""
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if not isinstance(payload, dict):
        return []
    for key in LIST_KEYS:
        value = payload.get(key)
        if isinstance(value, list):
            return [x for x in value if isinstance(x, dict)]
    return []


def _first(row: dict[str, Any], keys) -> Any:
    for key in keys:
        if key in row and row[key] not in (None, ""):
            return row[key]
    return None


def _nexthop(row: dict[str, Any]) -> dict[str, Any]:
    """
    Read the next hop in every shape Gaia R82 was observed to use.

    Verified against tests/fixtures/gaia_r82_probe.py, which is unedited output
    from the lab. Three shapes appear there and they are genuinely different:

        show-routes, routed     {"gateways": [{"address": .., "interface": ..}]}
        show-routes, connected  {"interface": "eth1"}          - no gateway, correctly
        show-static-routes      [{"gateway": .., "priority": ..}]

    Returns `understood: False` for anything else. That flag is what stops the
    parsed counter from claiming a route it only half read - the exact failure
    the first live probe exposed.
    """
    raw = row.get("next-hop", row.get("next_hop", row.get("nexthop")))
    if raw is None:
        # Some builds and some tables put the hop at the top level instead of
        # nesting it. Losing shape C to a rewrite aimed at shape A is exactly
        # the regression a fixture-backed suite is for.
        raw = _first(row, ("gateway", "via"))
    result = {"gateways": [], "interface": "", "understood": False,
              "kind": "unknown", "why": ""}

    if raw is None:
        interface = _first(row, INTERFACE_KEYS)
        if interface:
            result.update(interface=str(interface), understood=True, kind="connected")
        else:
            result["why"] = "no next-hop field and no interface"
        return result

    if isinstance(raw, str):
        result.update(gateways=[raw.strip()], understood=True, kind="gateway")
        return result

    if isinstance(raw, dict):
        gateways = raw.get("gateways")
        if isinstance(gateways, list):
            for entry in gateways:
                if isinstance(entry, dict):
                    address = str(entry.get("address") or entry.get("gateway") or "").strip()
                    if address and address not in result["gateways"]:
                        result["gateways"].append(address)
                    if not result["interface"] and entry.get("interface"):
                        result["interface"] = str(entry["interface"])
                elif isinstance(entry, str) and entry not in result["gateways"]:
                    result["gateways"].append(entry)
            if result["gateways"]:
                result.update(understood=True, kind="gateway")
                return result
        interface = _first(raw, INTERFACE_KEYS)
        if interface:
            # A connected route has no gateway, and that is the answer, not a gap.
            result.update(interface=str(interface), understood=True, kind="connected")
            return result
        result["why"] = f"next-hop object with keys {sorted(raw)} is not modelled"
        return result

    if isinstance(raw, list):
        for entry in raw:
            if isinstance(entry, dict):
                address = str(_first(entry, ("gateway", "address", "ip", "next-hop")) or "").strip()
                if address and address not in result["gateways"]:
                    result["gateways"].append(address)
                if not result["interface"] and entry.get("interface"):
                    result["interface"] = str(entry["interface"])
            elif isinstance(entry, str) and entry.strip():
                result["gateways"].append(entry.strip())
        if result["gateways"]:
            result.update(understood=True, kind="gateway")
        else:
            result["why"] = "next-hop list held no readable gateway"
        return result

    result["why"] = f"next-hop of type {type(raw).__name__} is not modelled"
    return result


def _prefix(row: dict[str, Any]) -> str | None:
    destination = _first(row, DEST_KEYS)
    if destination in (None, ""):
        return None
    text = str(destination).strip()
    if text.lower() in ("default", "default-route"):
        return "0.0.0.0/0"
    if "/" in text:
        try:
            return str(ip_network(text, strict=False))
        except ValueError:
            return None
    mask = _first(row, MASK_KEYS)
    if mask in (None, ""):
        return None
    try:
        return str(ip_network(f"{text}/{mask}", strict=False))
    except ValueError:
        return None


def _route_type(row: dict[str, Any], from_static: bool) -> str:
    value = str(_first(row, TYPE_KEYS) or "").strip()
    if value and value.lower() not in HOP_DESCRIPTORS:
        return value
    # Either absent, or a next-hop descriptor wearing the name `type`.
    return "Static" if from_static else "unknown"


def read_routes(payload: Any, source: str = "") -> dict[str, Any]:
    """
    Normalise one gateway's routing answer.

    `parsed` counts routes that were UNDERSTOOD, not routes whose prefix
    happened to be legible. The first live probe reported 7/7 while dropping
    every next hop, and a counter that can do that is worse than no counter.

    `source` is the command the payload came from. show-static-routes carries
    no protocol field, so without it the only honest label is "unknown" - and
    "these came from the static route table" is a fact the caller has.
    """
    from_static = "static" in str(source).lower()
    routes, unparsed = [], []
    unreadable = 0
    for row in _rows(payload):
        prefix = _prefix(row)
        if prefix is None:
            unparsed.append({"reason": "no destination prefix could be read", "raw": row})
            continue
        hop = _nexthop(row)
        if not hop["understood"]:
            unreadable += 1
        routes.append({
            "prefix": prefix,
            "next_hops": hop["gateways"],
            "interface": hop["interface"] or str(_first(row, INTERFACE_KEYS) or ""),
            "type": _route_type(row, from_static),
            "connected": hop["kind"] == "connected",
            "next_hop_kind": hop["kind"],
            "next_hop_read": hop["understood"],
            "next_hop_problem": hop["why"],
        })
    return {
        "routes": routes,
        "unparsed": unparsed,
        "parsed": len(routes) - unreadable,
        "next_hop_unreadable": unreadable,
        "total": len(routes) + len(unparsed),
    }


def _subnet_node_for(prefix: str, network: dict[str, Any]) -> str | None:
    for node in network.get("nodes", []) or []:
        if node.get("role") == "network" and str(node.get("name")) == prefix:
            return node["id"]
    return None


def _device_id(network: dict[str, Any], name_or_ip: str) -> str | None:
    for node in network.get("nodes", []) or []:
        if node.get("role") in ("interface", "network"):
            continue
        if str(node.get("name")) == name_or_ip:
            return node["id"]
        if name_or_ip in (node.get("ips") or []):
            return node["id"]
    return None


def add_routing(network: dict[str, Any], per_gateway: dict[str, Any]) -> dict[str, Any]:
    """
    Overlay routing onto an existing network map.

    `per_gateway` maps a gateway name or address to the result of read_routes().

    Three shapes of edge come out of this, and they are different claims:

      gateway -> gateway   the next hop is an address the map already knows.
                           "External-GW01 reaches 192.168.10.0/24 through
                           Internal-GW01" is a relationship an interface-only
                           map could never draw, and it is the reason this
                           feature exists.
      gateway -> prefix    the next hop is outside the map, so the prefix
                           becomes a node of its own. The gateway says it can
                           reach it; nothing here says what is in it.
      nothing              a connected route to a subnet already on the map.
                           The interface edge already carries that, and a
                           second parallel line would only add ink - so it is
                           counted as confirmation instead of drawn.
    """
    nodes = list(network.get("nodes", []) or [])
    edges = list(network.get("edges", []) or [])
    limitations = list(network.get("limitations", []) or [])
    known = {n["id"] for n in nodes}

    parsed = unreadable = unparsed = confirmed = 0
    skipped: list[str] = []
    unreachable_gateways: list[str] = []

    for gateway, result in (per_gateway or {}).items():
        if isinstance(result, dict) and result.get("error"):
            unreachable_gateways.append(f"{gateway} ({result['error']})")
            continue

        device = _device_id(network, str(gateway))
        if device is None:
            unreachable_gateways.append(
                f"{gateway} (answered, but is not a node on this map)")
            continue

        parsed += int((result or {}).get("parsed") or 0)
        unreadable += int((result or {}).get("next_hop_unreadable") or 0)
        unparsed += len((result or {}).get("unparsed") or [])

        for route in (result or {}).get("routes") or []:
            prefix = route["prefix"]
            if prefix in SKIP_PREFIXES:
                if prefix not in skipped:
                    skipped.append(prefix)
                continue

            on_map = _subnet_node_for(prefix, network)

            # A connected route to a subnet the map already draws from an
            # interface address adds no information, only a second line.
            if route.get("connected") and on_map is not None:
                confirmed += 1
                continue

            hop_device = None
            for hop in route["next_hops"]:
                hop_device = _device_id(network, hop)
                if hop_device and hop_device != device:
                    break
                hop_device = None

            target = hop_device or on_map
            if target is None:
                target = f"route:{prefix}"
                if target not in known:
                    nodes.append({
                        "id": target, "name": prefix, "type": "routed-network",
                        "role": "routed-network", "ips": [prefix],
                        "default_route": prefix == "0.0.0.0/0",
                    })
                    known.add(target)

            via = ", ".join(route["next_hops"]) or "connected"
            label = (f"{prefix} via {via}" if hop_device
                     else f"{route['type']} via {via}")
            edges.append({
                "from": device, "to": target, "kind": "route",
                "label": label if route["next_hop_read"]
                else f"{prefix} · next hop not readable",
                "route_type": route["type"],
                "prefix": prefix,
                "next_hops": route["next_hops"],
                "interface": route["interface"],
                "next_hop_read": route["next_hop_read"],
                "through_device": bool(hop_device),
            })

    limitations.append(
        "Routing comes from the Gaia API on each gateway and is a snapshot of "
        "the routing table at read time, not a live view. Dynamic routes can "
        "change between this read and the next packet.")
    if skipped:
        limitations.append(
            "Not drawn because they describe the gateway itself rather than the "
            "estate: " + ", ".join(skipped) + ".")
    if unreadable:
        limitations.append(
            f"{unreadable} route(s) were read but their next hop was in a shape "
            "this build of the reader does not model, so the line is drawn "
            "without a hop. Run tools/probe_gaia.py and send the output.")
    if unparsed:
        limitations.append(
            f"{unparsed} route entr(y/ies) could not be read at all and are NOT "
            "drawn. Run tools/probe_gaia.py and narrow the readers in "
            "app/gaia_topology.py to this build's shape.")
    if unreachable_gateways:
        limitations.append(
            "No routing was read from: " + "; ".join(sorted(unreachable_gateways))
            + ". Those gateways are drawn without their routes, which can make "
            "the map look like they have none.")

    return {
        **network,
        "nodes": nodes,
        "edges": edges,
        "count": len(nodes),
        "limitations": limitations,
        "routing": {
            "gateways_read": len(per_gateway or {}) - len(unreachable_gateways),
            "routes_parsed": parsed,
            "routes_unparsed": unparsed,
            "next_hop_unreadable": unreadable,
            "connected_confirmed": confirmed,
            "skipped_prefixes": skipped,
            "unreachable": unreachable_gateways,
        },
    }
