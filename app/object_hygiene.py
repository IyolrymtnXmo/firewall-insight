"""
Object hygiene: unused, duplicated, and groups that could be written shorter.

Pure functions over object definitions already read by `estate_reads`.

UNUSED is not computed here. The Management Server answers it itself with
`show-unused-objects`, across every layer, package, NAT rule, group, VPN
community and gateway topology it knows about. Anything this module could
infer from the rulebases it was given would only know about those rulebases,
and "not in these rules" is not "unused".

DUPLICATES are objects with different names and the same definition: two hosts
at one address, two networks with one subnet. Each is a fact about the
definitions, but merging them is not free - a name appears in logs, in
reports, and in whatever else refers to it - so a duplicate is reported with
every name, never with a recommendation of which to keep.

MERGES are groups whose address members collapse, exactly, to fewer CIDR
blocks: four hosts .0-.3 are one /30. "Exactly" is the whole constraint. The
suggested block covers precisely the addresses the members covered, never one
more, because widening a group is how an allow rule quietly starts allowing
something nobody asked for.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from typing import Any


def _predefined(o: dict[str, Any]) -> bool:
    return bool(o.get("read-only")) or (o.get("domain") or {}).get("domain-type") == "data domain"


def _v4_network(o: dict[str, Any]) -> list[ipaddress.IPv4Network] | None:
    """The IPv4 addresses one object stands for, or None if it is not a plain address."""
    try:
        kind = o.get("type")
        if kind == "host" and o.get("ipv4-address"):
            return [ipaddress.ip_network(f"{o['ipv4-address']}/32")]
        if kind == "network" and o.get("subnet4") and o.get("mask-length4") is not None:
            return [ipaddress.ip_network(f"{o['subnet4']}/{o['mask-length4']}", strict=False)]
        if kind == "address-range" and o.get("ipv4-address-first") and o.get("ipv4-address-last"):
            first = ipaddress.ip_address(o["ipv4-address-first"])
            last = ipaddress.ip_address(o["ipv4-address-last"])
            return list(ipaddress.summarize_address_range(first, last))
    except ValueError:
        return None
    return None


def _signature(o: dict[str, Any]) -> tuple | None:
    kind = o.get("type")
    if kind == "host":
        v4, v6 = o.get("ipv4-address"), o.get("ipv6-address")
        return ("host", v4, v6) if (v4 or v6) else None
    if kind == "network":
        if o.get("subnet4"):
            return ("network", o.get("subnet4"), o.get("mask-length4"))
        if o.get("subnet6"):
            return ("network6", o.get("subnet6"), o.get("mask-length6"))
        return None
    if kind == "address-range":
        first, last = o.get("ipv4-address-first"), o.get("ipv4-address-last")
        return ("address-range", first, last) if first and last else None
    return None


def duplicates(definitions: dict[str, Any]) -> list[dict[str, Any]]:
    """Objects of one type that define the same thing under different names."""
    buckets: dict[tuple, list[dict[str, Any]]] = defaultdict(list)
    for kind in ("host", "network", "address-range"):
        for o in (definitions.get(kind) or {}).get("objects") or []:
            if _predefined(o):
                continue
            sig = _signature(o)
            if sig:
                buckets[sig].append(o)
    out = []
    for sig, objs in buckets.items():
        if len(objs) < 2:
            continue
        out.append({
            "type": sig[0],
            "definition": " - ".join(str(x) for x in sig[1:] if x not in (None, "")),
            "objects": [{"uid": o.get("uid"), "name": o.get("name"),
                         "comments": o.get("comments") or ""} for o in objs],
        })
    out.sort(key=lambda d: (-len(d["objects"]), d["type"], d["definition"]))
    return out


def merge_suggestions(definitions: dict[str, Any]) -> list[dict[str, Any]]:
    """Groups whose address members collapse, exactly, into fewer blocks."""
    by_uid: dict[str, dict[str, Any]] = {}
    for kind in ("host", "network", "address-range"):
        for o in (definitions.get(kind) or {}).get("objects") or []:
            if o.get("uid"):
                by_uid[o["uid"]] = o

    out = []
    for g in (definitions.get("group") or {}).get("objects") or []:
        members = g.get("members") or []
        address_members, blocks, other = [], [], 0
        for m in members:
            mo = m if isinstance(m, dict) else {"uid": m}
            full = by_uid.get(mo.get("uid")) or mo
            nets = _v4_network(full)
            if nets is None:
                other += 1
                continue
            address_members.append(full)
            blocks.extend(nets)
        if len(address_members) < 2:
            continue
        collapsed = list(ipaddress.collapse_addresses(blocks))
        if len(collapsed) >= len(address_members):
            continue
        before = sum(n.num_addresses for n in blocks)
        after = sum(n.num_addresses for n in collapsed)
        # collapse_addresses never widens, but overlapping members would make
        # "before" count some addresses twice. Equality of the union is what
        # matters, and it holds by construction; the counts are informational.
        out.append({
            "group": g.get("name"), "group_uid": g.get("uid"),
            "members": [{"uid": m.get("uid"), "name": m.get("name"), "type": m.get("type")}
                        for m in address_members],
            "equivalent_to": [str(n) for n in collapsed],
            "member_count": len(address_members),
            "block_count": len(collapsed),
            "addresses": after,
            "overlapping_members": before != after,
            "other_members_unchanged": other,
        })
    out.sort(key=lambda s: s["block_count"] - s["member_count"])
    return out


def unused_summary(unused: list[dict[str, Any]]) -> dict[str, Any]:
    by_type: dict[str, int] = defaultdict(int)
    rows = []
    for o in unused:
        by_type[str(o.get("type"))] += 1
        rows.append({
            "uid": o.get("uid"), "name": o.get("name"), "type": o.get("type"),
            "address": (o.get("ipv4-address") or
                        (f"{o.get('subnet4')}/{o.get('mask-length4')}" if o.get("subnet4") else "") or
                        (f"{o.get('ipv4-address-first')}-{o.get('ipv4-address-last')}"
                         if o.get("ipv4-address-first") else "")),
            "comments": o.get("comments") or "",
            "predefined": _predefined(o),
        })
    return {"by_type": dict(sorted(by_type.items())), "objects": rows}


NOTES = [
    "Unused is the Management Server's own answer (show-unused-objects), not an "
    "inference from the rulebases on screen.",
    "A duplicate is two names for one definition. Which name to keep depends on "
    "logs, reports and references this page cannot see; use where-used first.",
    "A merge suggestion covers exactly the addresses the members covered - never "
    "more. Replacing members still changes names that appear in logs.",
]
