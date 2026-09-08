"""
Put a traced path on the network map.

Chapter 6 set this as the hard one, and the difficulty is not drawing - it is
that the two models share no vocabulary. `topology_map.network_map()` knows
gateways, interfaces and the subnets it derived from interface addresses.
`traffic.trace_access_tree()` knows rules, layers, an action and a tri-state
confidence. Neither knows anything the other holds.

The join is the one thing in both worlds that is an address: the source and
destination the person typed, tested against the map's subnets. Containment is
a fact - an IP either is or is not inside a prefix - so the endpoints are the
solid part of the overlay.

Everything past the join is weaker, and it is weak in a DIFFERENT way from the
verdict, so the overlay carries two confidences:

    policy_confidence    does the rulebase decide this flow          (Chapter 4)
    topology_confidence  does the packet actually pass through here  (this file)

They fail apart from each other. `accept` proven exactly, to 8.8.8.8, is a
certain verdict over a path the map cannot see: there is no route to the
internet in `show-gateways-and-servers`, only an interface a gateway flagged
as leading there. Drawing that like a LAN-to-LAN hop would assert something no
API field supports.

`draw` is therefore the weaker of the two, and the frontend styles the path by
it. An `unknown` path must never look like an `exact` one - that is the
homework's explicit warning, and it is the same rule README principle 10 puts
on every other surface in this application.
"""

from __future__ import annotations

from ipaddress import ip_address, ip_network
from typing import Any

# Weakest-link ordering. `none` means there is nothing to draw at all.
_RANK = {"exact": 3, "inferred": 2, "unverified": 1, "unknown": 1, "none": 0}
_POLICY_TO_DRAW = {"exact": "exact", "inferred": "inferred",
                   "unknown": "unverified", "none": "none", "": "none"}


def _weakest(*values: str) -> str:
    """The weakest link, keeping each label as it was written.

    `unknown` and `unverified` rank the same but are not the same word:
    `unknown` describes what we know about the topology, `unverified` is how
    the result is drawn. Only `draw` translates between them.
    """
    return min(values, key=lambda v: _RANK.get(v, 0))


def _addr(text: str):
    try:
        return ip_address(str(text or "").strip())
    except ValueError:
        return None


def _subnet_nodes(network: dict[str, Any]) -> list[tuple[Any, dict[str, Any]]]:
    out = []
    for node in network.get("nodes", []) or []:
        if node.get("role") != "network":
            continue
        try:
            out.append((ip_network(str(node.get("name")), strict=False), node))
        except ValueError:
            continue
    return out


def _owners(network: dict[str, Any]) -> dict[str, list[str]]:
    """subnet node id -> device uids whose interfaces sit on it."""
    parent = {n["id"]: n.get("parent") for n in network.get("nodes", [])
              if n.get("role") == "interface" and n.get("id")}
    out: dict[str, list[str]] = {}
    for edge in network.get("edges", []) or []:
        if edge.get("label") != "connected subnet":
            continue
        dev = parent.get(edge.get("from"))
        if not dev:
            continue
        out.setdefault(str(edge.get("to")), [])
        if dev not in out[str(edge.get("to"))]:
            out[str(edge.get("to"))].append(dev)
    return out


def _endpoint(network: dict[str, Any], text: str) -> dict[str, Any]:
    """Where this address sits on the map. The most specific prefix wins."""
    ip = _addr(text)
    if ip is None:
        return {"ip": str(text), "node_id": None, "state": "unresolved",
                "detail": f"'{text}' is not an IP address, so it cannot be placed "
                          "on the map. The trace itself may still have resolved it."}
    best = None
    for net, node in _subnet_nodes(network):
        if ip.version != net.version or ip not in net:
            continue
        if best is None or net.prefixlen > best[0].prefixlen:
            best = (net, node)
    if best is None:
        return {"ip": str(ip), "node_id": None, "state": "off-map",
                "detail": f"{ip} is not inside any subnet the map derived from "
                          "interface addresses."}
    return {"ip": str(ip), "node_id": best[1]["id"], "state": "on-map",
            "detail": f"{ip} is inside {best[0]}"}


def _external_subnet(network: dict[str, Any]) -> dict[str, Any] | None:
    for node in network.get("nodes", []) or []:
        if node.get("role") == "network" and node.get("external"):
            return node
    return None


def _device(network: dict[str, Any], uid: str) -> dict[str, Any]:
    for node in network.get("nodes", []) or []:
        if node.get("id") == uid:
            return node
    return {"id": uid, "name": uid}


def trace_overlay(
    network: dict[str, Any],
    src: str,
    dst: str,
    access: dict[str, Any],
) -> dict[str, Any]:
    winner = access.get("winner") or access.get("possible_winner") or {}
    policy_confidence = str(access.get("confidence") or "none")

    source = _endpoint(network, src)
    destination = _endpoint(network, dst)
    owners = _owners(network)
    limitations: list[str] = []

    src_owners = owners.get(str(source.get("node_id")), [])
    dst_owners = owners.get(str(destination.get("node_id")), [])

    # An off-map endpoint is only placed when a gateway itself said one of its
    # interfaces leads to the internet. That is an API field, not a guess about
    # the address - but it is still an entry point, not a route, so it can
    # never make the topology exact.
    for side, ep, other_owners in (("source", source, dst_owners),
                                   ("destination", destination, src_owners)):
        if ep["state"] != "off-map":
            continue
        ext = _external_subnet(network)
        if ext is not None and owners.get(ext["id"]):
            ep["via_node_id"] = ext["id"]
            ep["detail"] += (f" It is drawn beyond {ext['name']}, which a gateway "
                             "flagged leads-to-internet.")
            limitations.append(
                f"The {side} address is not on the map. It is shown beyond the "
                f"subnet a gateway flagged leads-to-internet ({ext['name']}); the "
                "actual route past that interface is not in the object model.")
        else:
            limitations.append(
                f"The {side} address is not on the map and no interface reports "
                "leads-to-internet, so no path is drawn to it.")

    topology_confidence = "exact"
    hops: list[dict[str, Any]] = []

    if source["state"] == "unresolved" or destination["state"] == "unresolved":
        topology_confidence = "unknown"
    elif not network.get("nodes"):
        topology_confidence = "none"
        limitations.append("The network map has no nodes, so there is nothing to "
                           "draw the path on. Load the map first.")
    else:
        shared = [d for d in src_owners if d in dst_owners]
        start = source.get("node_id") or source.get("via_node_id")
        end = destination.get("node_id") or destination.get("via_node_id")

        if start:
            hops.append({"node_id": start, "kind": "network",
                         "name": _device(network, start).get("name", start)})
        if shared:
            dev = _device(network, shared[0])
            hops.append({"node_id": dev["id"], "kind": "device",
                         "name": dev.get("name", dev["id"]),
                         "role": dev.get("role", "gateway")})
            if len(shared) > 1:
                topology_confidence = _weakest(topology_confidence, "inferred")
                limitations.append(
                    "More than one enforcement point connects both subnets ("
                    + ", ".join(_device(network, d).get("name", d) for d in shared)
                    + "); which one carries the flow depends on routing, which "
                    "show-gateways-and-servers does not expose.")
        else:
            for dev_uid in src_owners + [d for d in dst_owners if d not in src_owners]:
                dev = _device(network, dev_uid)
                hops.append({"node_id": dev["id"], "kind": "device",
                             "name": dev.get("name", dev["id"]),
                             "role": dev.get("role", "gateway")})
            if src_owners and dst_owners:
                topology_confidence = _weakest(topology_confidence, "inferred")
                limitations.append(
                    "The two subnets are behind more than one enforcement point ("
                    + ", ".join(
                        _device(network, d).get("name", d)
                        for d in src_owners + [x for x in dst_owners if x not in src_owners])
                    + "). The hop between them is routing, which the map does not know.")
        if end and end != start:
            hops.append({"node_id": end, "kind": "network",
                         "name": _device(network, end).get("name", end)})

        if source["state"] == "off-map" or destination["state"] == "off-map":
            topology_confidence = _weakest(
                topology_confidence,
                "inferred" if (source.get("via_node_id") or destination.get("via_node_id"))
                else "unknown")
        if not hops:
            topology_confidence = "none"

    draw = _weakest(_POLICY_TO_DRAW.get(policy_confidence, "none"), topology_confidence)
    if draw == "unknown":
        draw = "unverified"

    return {
        "source": source,
        "destination": destination,
        "hops": hops,
        "verdict": access.get("result") or "No matching rule",
        "rule": winner.get("display_rule") or winner.get("rule"),
        "rule_name": winner.get("name") or "",
        "layer": winner.get("layer") or "",
        "reached": bool(access.get("matched")),
        "policy_confidence": policy_confidence,
        "topology_confidence": topology_confidence,
        "draw": draw,
        "limitations": limitations + [
            "The path is drawn from configured interface addresses and the policy "
            "verdict. It is not a route: no routing table, VPN tunnel or PBR rule "
            "is visible to this application.",
        ],
    }
