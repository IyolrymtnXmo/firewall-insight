"""
Rule usage from the firewall logs, alongside the hit counter.

WHY A SECOND SOURCE
The hit counter resets on policy install and on gateway restart, so "zero hits"
often means "installed on Tuesday". Logs are a separate record, kept by the log
server, over a window you choose.

WHY IT IS NOT THE ANSWER EITHER
A log only exists for a rule that logs. A rule tracked `None` produces no log
records however much traffic it carries, so "no logs" says nothing about it.
And this Management API version cannot count - it has no aggregate query and
ignores a filter on rule uid - so usage is counted by reading records, newest
first, up to a cap. When the cap is reached the window held more records than
were read, and a rule with no record among them is "not among the most recent
N", not "unused".

So every rule gets one of these, and only one says anything about disuse:

    seen             N records in the window; last seen at T
    no-traffic       logs, the scan covered the whole window, and nothing
                     matched it                    <- the only disuse finding
    not-in-sample    logs, but the scan stopped at the cap before the
                     window ended                  <- cannot tell
    not-logged       track is None                 <- cannot tell
    track-unknown    track could not be resolved   <- cannot tell
    via-inline       holds an inline layer; its traffic is logged against the
                     inline rules                  <- see those rules
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

VERDICTS = ("seen", "no-traffic", "not-in-sample", "not-logged", "track-unknown",
            "via-inline")


def aggregate(records: list[dict[str, Any]], package: str) -> dict[str, Any]:
    per_rule: dict[str, dict[str, Any]] = {}
    other_policy = 0
    no_uid = 0
    for rec in records:
        policy = rec.get("policy_name")
        if policy and package and policy != package:
            other_policy += 1
            continue
        uid = rec.get("rule_uid")
        if not uid:
            no_uid += 1
            continue
        row = per_rule.setdefault(uid, {"count": 0, "first": None, "last": None,
                                        "actions": defaultdict(int)})
        row["count"] += 1
        t = rec.get("time")
        if t:
            row["first"] = t if row["first"] is None or t < row["first"] else row["first"]
            row["last"] = t if row["last"] is None or t > row["last"] else row["last"]
        row["actions"][str(rec.get("action") or "")] += 1
    for row in per_rule.values():
        row["actions"] = dict(row["actions"])
    oldest = min((r.get("time") for r in records if r.get("time")), default=None)
    return {"per_rule": per_rule, "other_policy": other_policy, "no_uid": no_uid,
            "read": len(records), "oldest_read": oldest}


def usage(rules: list[dict[str, Any]], agg: dict[str, Any], *, capped: bool,
          time_frame: str) -> dict[str, Any]:
    rows = []
    counts: dict[str, int] = defaultdict(int)
    for r in rules:
        seen = agg["per_rule"].get(r.get("uid") or "")
        track = str(r.get("track") or "")
        if seen:
            verdict, note = "seen", f"{seen['count']} record(s) in the window"
        elif r.get("inline_layer"):
            verdict, note = "via-inline", (f"holds inline layer {r['inline_layer']}; traffic "
                                           "is logged against the rules inside it")
        elif track.lower() == "none":
            verdict, note = "not-logged", "tracking is None, so logs cannot show its use"
        elif not track or track == "unresolved":
            verdict, note = "track-unknown", "whether this rule logs could not be read"
        elif capped:
            verdict, note = "not-in-sample", (f"not among the {agg['read']:,} most recent records; "
                                              "the window held more than were read")
        else:
            verdict, note = "no-traffic", f"logs, and no record matched it in {time_frame}"
        counts[verdict] += 1
        rows.append({
            "uid": r.get("uid"), "display_rule": r.get("display_rule"),
            "name": r.get("name"), "layer": r.get("layer"), "action": r.get("action"),
            "enabled": r.get("enabled"), "track": track or None,
            "hits": r.get("hits"), "last_hit": r.get("last_hit"),
            "logs": seen["count"] if seen else 0,
            "first_seen": seen["first"] if seen else None,
            "last_seen": seen["last"] if seen else None,
            "actions": seen["actions"] if seen else {},
            "verdict": verdict, "note": note,
            # The two sources disagreeing is worth a look either way.
            "disagrees": bool((r.get("hits") or 0) == 0 and seen)
                         or bool((r.get("hits") or 0) > 0 and verdict == "no-traffic"),
        })
    notes = [
        f"Read {agg['read']:,} firewall log record(s) from {time_frame}"
        + (", stopping at the cap before the window ended." if capped else ", the whole window."),
        "Only 'no-traffic' is evidence of disuse. Every other verdict without a "
        "record is a statement about what the logs cannot show.",
    ]
    if agg["other_policy"]:
        notes.append(f"{agg['other_policy']:,} record(s) belonged to another policy "
                     "package and were not counted.")
    if agg["no_uid"]:
        notes.append(f"{agg['no_uid']:,} record(s) carried no rule uid (implied rules, for "
                     "instance) and were not counted.")
    return {"time_frame": time_frame, "capped": capped, "read": agg["read"],
            "oldest_read": agg["oldest_read"], "counts": {v: counts.get(v, 0) for v in VERDICTS},
            "rules": rows, "notes": notes}
