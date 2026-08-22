"""
Topology graph: turn `show-gateways-and-servers` into nodes and edges.

Split out of traffic.py in v4.16. traffic.py held four concerns - the
tri-state matcher, the path trace, NAT correlation and this graph - and the
cluster and management-HA work here pushed it past the 700-line guard the
structure test enforces.

Everything drawn here comes from fields the Management API returned. Where a
relationship is not in the payload it is not drawn, and the reason goes into
`limitations` so the map explains its own gaps rather than looking broken.
"""

from __future__ import annotations

from ipaddress import ip_network
from typing import Any

CLUSTER_TYPES = {
    "CpmiGatewayCluster", "simple-cluster", "gateway-cluster",
    "CpmiVsxClusterNetobj", "CpmiVsClusterNetobj",
}
# The member type string changed in R81.20; both are still in the field.
MEMBER_TYPES = {"cluster-member", "CpmiClusterMember", "CpmiVsxClusterMember"}


def _cluster_member_names(o: dict[str, Any]) -> list[str]:
    """Member names as the cluster object itself reports them.

    Verified against R82: `show-gateways-and-servers` at details-level full
    already carries `cluster-member-names`, so no extra call is needed. Older
    builds expose `cluster-members` as a list of objects instead.

    This is deliberately the ONLY source of membership. Reading it off the
    addresses - a /30 with .1 and .2 looks like sync, a third address on a
    member's subnet looks like a VIP - is right most of the time and wrong
    some of the time, and a map that is "usually right" about which boxes are
    one firewall is worse than one that says it does not know.
    """
    for key in ("cluster-member-names", "cluster-members", "members"):
        v = o.get(key)
        if not isinstance(v, list) or not v:
            continue
        out = [m.get("name") if isinstance(m, dict) else str(m) for m in v]
        return [n for n in out if n]
    return []


def _mgmt_role(o: dict[str, Any]) -> str | None:
    """primary / secondary, from management-blades.

    A management server carries no pointer to its HA peer, but it does say
    whether it is a secondary: `management-blades.secondary` is true on the
    standby. A domain has exactly one primary, so primary + secondary IS the
    HA pair - that is the definition, not an inference from addresses.

    What this does NOT tell us is whether the two are currently synchronised.
    That is a live state the object model does not carry, so the map may only
    say that HA is configured, never that it is healthy.
    """
    blades = o.get("management-blades") or o.get("management_blades")
    if not isinstance(blades, dict):
        return None
    if not (blades.get("network-policy-management") or blades.get("network_policy_management")):
        return None
    return "secondary" if blades.get("secondary") else "primary"


def _role_for(typ: str, name: str, o: dict[str, Any]) -> str:
    if typ in CLUSTER_TYPES:
        return "cluster"
    if typ in MEMBER_TYPES:
        return "cluster-member"
    if typ == "simple-gateway" or "gateway" in typ.lower():
        return "gateway"
    if typ == "checkpoint-host" or "management" in name.lower() or "mgmt" in name.lower():
        return "management"
    return "device"


def network_map(objects: list[dict[str, Any]]) -> dict[str, Any]:
    nodes = []
    edges = []
    subnet_nodes: dict[str, dict[str, Any]] = {}
    by_name: dict[str, str] = {}          # object name -> uid
    limitations = [
        "Connected subnets are calculated from configured interface IPv4 address and mask.",
        "Links show configured logical relationships only; physical cabling, switches and live routing are not inferred.",
    ]

    for o in objects:
        uid = o.get("uid")
        name = o.get("name") or uid
        typ = o.get("type", "")
        if not uid:
            continue
        by_name[str(name)] = uid
        ips = [str(o[k]) for k in ("ipv4-address", "ip-address") if o.get(k)]
        role = _role_for(typ, str(name), o)

        node: dict[str, Any] = {"id": uid, "name": name, "type": typ, "role": role, "ips": ips}
        if role == "cluster":
            node["members"] = _cluster_member_names(o)
        if role == "management":
            mr = _mgmt_role(o)
            if mr:
                node["mgmt_role"] = mr
        nodes.append(node)

        ifaces = o.get("interfaces") if isinstance(o.get("interfaces"), list) else []
        for i, iface in enumerate(ifaces):
            if not isinstance(iface, dict):
                continue
            ip = iface.get("ipv4-address") or iface.get("ip-address")
            mask = (iface.get("ipv4-mask-length") or iface.get("mask-length4")
                    or iface.get("mask-length"))
            if not ip or str(ip) == "0.0.0.0":
                continue
            iname = iface.get("name") or f"interface {i+1}"
            nid = f"{uid}:if:{i}"
            cidr = f"{ip}/{mask}" if mask is not None else str(ip)
            inode = {"id": nid, "name": iname, "type": "interface", "role": "interface",
                     "ips": [str(ip)], "cidr": cidr, "parent": uid}
            topo = iface.get("topology")
            if isinstance(topo, dict) and topo.get("leads-to-internet"):
                inode["external"] = True          # the gateway says so, we do not guess
            nodes.append(inode)
            edges.append({"from": uid, "to": nid, "label": "interface"})
            if mask is not None:
                try:
                    net = str(ip_network(cidr, strict=False))
                except ValueError:
                    continue
                sid = f"net:{net}"
                if sid not in subnet_nodes:
                    subnet_nodes[sid] = {"id": sid, "name": net, "type": "network",
                                         "role": "network", "ips": [net]}
                if inode.get("external"):
                    subnet_nodes[sid]["external"] = True
                edges.append({"from": nid, "to": sid, "label": "connected subnet"})

    # ---- cluster membership -------------------------------------------
    # A member object carries no back-reference to its cluster, so the edge
    # can only come from the cluster's own list.
    missing: list[str] = []
    for n in nodes:
        if n.get("role") != "cluster":
            continue
        resolved = []
        for mname in n.get("members") or []:
            muid = by_name.get(mname)
            if not muid:
                missing.append(mname)
                continue
            resolved.append(muid)
            edges.append({"from": n["id"], "to": muid, "label": "cluster member",
                          "kind": "membership"})
        n["member_ids"] = resolved
    if missing:
        limitations.append(
            "Cluster members not returned by show-gateways-and-servers, so they are "
            "not on the map: " + ", ".join(sorted(set(missing))) + ".")

    # ---- management HA -------------------------------------------------
    primaries = [n for n in nodes if n.get("mgmt_role") == "primary"]
    secondaries = [n for n in nodes if n.get("mgmt_role") == "secondary"]
    if len(primaries) == 1 and secondaries:
        for sec in secondaries:
            edges.append({"from": primaries[0]["id"], "to": sec["id"],
                          "label": "management HA", "kind": "mgmt-ha"})
        limitations.append(
            "Management HA is shown as configured (one primary, "
            f"{len(secondaries)} secondary), from management-blades. Whether the "
            "peers are currently synchronised is not exposed by the object model.")
    elif len(primaries) > 1:
        limitations.append(
            f"{len(primaries)} management servers report the primary role, so no "
            "HA pairing is drawn - the object model cannot say which pairs with which.")

    nodes.extend(subnet_nodes.values())
    return {"nodes": nodes, "edges": edges, "count": len(nodes),
            "topology": True, "limitations": limitations}
