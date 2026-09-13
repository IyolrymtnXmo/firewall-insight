"""
Reads added in v4.39, kept together so the command surface stays auditable.

    show-unused-objects   objects the Management Server itself says are unused
    show-hosts / show-networks / show-address-ranges / show-groups
                          object definitions, for duplicate and merge analysis
    where-used            what refers to one object
    show-logs             firewall log records, for rule usage over a window

Every one is a read. None of them is a `show-*` in the case of `where-used`,
which is why they are listed rather than trusted to a prefix.

Every function here pages and stops at a cap, and says whether it stopped. A
list that was cut short is reported as cut short: "no duplicates among the
first 2,000 hosts" is a different statement from "no duplicates", and the
analysis modules downstream keep the two apart.

All reads run under `heavy_lock`, the same lock the package tree uses, so a log
scan and a policy analysis never compete for the Management Server's rate
limit at the same moment.
"""

from __future__ import annotations

from typing import Any

from .runtime import heavy_lock

# The commands this module may issue. tests/test_v439_features.py holds it to
# this set, and every entry is a read.
READ_COMMANDS = frozenset({
    "show-unused-objects", "show-hosts", "show-networks", "show-address-ranges",
    "show-groups", "where-used", "show-logs",
})

PAGE = 500


async def _paged(c, command: str, cap: int, extra: dict[str, Any] | None = None):
    """Objects from a `show-*` list command, up to *cap*.

    Returns (objects, total_reported, capped).
    """
    assert command in READ_COMMANDS, command
    items: list[dict[str, Any]] = []
    offset, total = 0, None
    async with heavy_lock:
        while len(items) < cap:
            payload = {"limit": min(PAGE, cap - len(items)), "offset": offset,
                       "details-level": "full"}
            payload.update(extra or {})
            page = await c.call(command, payload)
            batch = [o for o in page.get("objects") or [] if isinstance(o, dict)]
            items.extend(batch)
            total = int(page.get("total") or 0)
            to = page.get("to")
            offset = int(to) if to is not None else offset + len(batch)
            if not batch or offset >= total:
                break
    capped = total is not None and len(items) < total
    return items, total if total is not None else len(items), capped


async def unused_objects(c, cap: int = 2000):
    return await _paged(c, "show-unused-objects", cap)


async def object_definitions(c, cap: int = 2000) -> dict[str, Any]:
    """Hosts, networks, ranges and groups, each with its own cap flag."""
    out: dict[str, Any] = {}
    for kind, command in (("host", "show-hosts"), ("network", "show-networks"),
                          ("address-range", "show-address-ranges"),
                          ("group", "show-groups")):
        items, total, capped = await _paged(c, command, cap)
        out[kind] = {"objects": items, "total": total, "capped": capped}
    return out


async def where_used(c, uid: str) -> dict[str, Any]:
    async with heavy_lock:
        return await c.call("where-used", {"uid": uid, "details-level": "standard"})


# Log windows the Management API accepts, offered as-is so nobody types one the
# server rejects.
TIME_FRAMES = ("last-hour", "today", "last-24-hours", "yesterday", "this-week",
               "last-7-days", "this-month", "last-30-days")


async def log_records(c, time_frame: str, cap: int = 3000, per_page: int = 100):
    """Firewall log records in *time_frame*, newest first, up to *cap*.

    This server version cannot aggregate: `type: count` and `top` are both
    rejected, and a filter on `rule_uid` returns nothing even for a uid that
    appears in the records (measured on the lab, API 2.0.1). So usage is
    counted by reading records. Only the fields the count needs are kept - a
    log record also carries source and destination addresses, and there is no
    reason to hold those in memory or return them.

    Returns (records, capped).
    """
    assert time_frame in TIME_FRAMES, time_frame
    keep = ("rule_uid", "rule", "rule_name", "layer_name", "policy_name",
            "time", "action")
    records: list[dict[str, Any]] = []
    async with heavy_lock:
        page = await c.call("show-logs", {"new-query": {
            "time-frame": time_frame, "max-logs-per-request": per_page,
            "filter": 'blade:"Firewall"'}})
        while True:
            batch = page.get("logs") or []
            for rec in batch:
                records.append({k: rec.get(k) for k in keep})
                if len(records) >= cap:
                    return records, True
            query_id = page.get("query-id")
            if not batch or not query_id or len(batch) < per_page:
                return records, False
            page = await c.call("show-logs", {"query-id": query_id})
