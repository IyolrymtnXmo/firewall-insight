"""
Trends: what the stored reviews, snapshots and health readings say over time.

Nothing here is sampled or interpolated. A point exists because a review ran, a
snapshot was taken or a reading was saved; between two points there is no data,
and a chart must draw a gap there rather than a line.

A review whose compliance section was not requested has no compliance point.
A review whose compliance section failed to run has a point marked `failed` -
not zero failures. The same for gateway health and for the change counters.
Plotting "could not read" as zero is the flattening this application refuses
everywhere else, and a trend line is where it would be least visible.
"""

from __future__ import annotations

from typing import Any

from .jobs.store import REAL_CHANGE_KEYS


def _section(run: dict[str, Any], name: str) -> tuple[str, dict[str, Any] | None]:
    s = (run.get("sections") or {}).get(name) or {}
    if not s.get("requested", True) and not s.get("ok"):
        return "not-requested", None
    if not s.get("ok"):
        return "failed", None
    return "ok", s.get("data") or {}


def review_points(runs: list[dict[str, Any]], package: str | None = None) -> list[dict[str, Any]]:
    """One point per stored review, oldest first."""
    points = []
    for run in sorted(runs, key=lambda r: str(r.get("started_at") or "")):
        if package and run.get("package") != package:
            continue
        p: dict[str, Any] = {"id": run.get("id"), "at": run.get("started_at"),
                             "package": run.get("package"), "complete": run.get("complete")}

        state, access = _section(run, "access")
        if state == "ok":
            s = access.get("summary") or {}
            dq = access.get("data_quality") or {}
            p["access"] = {
                "optimization_score": s.get("optimization_score"),
                "rules": s.get("analyzed_rules", s.get("total_rules")),
                "top_level_rules": s.get("top_level_rules"),
                "shadowed": s.get("potential_shadowed_or_redundant"),
                "duplicates": s.get("duplicate_groups"),
                "any_any_any": s.get("any_any_any_rules"),
                "zero_hit": s.get("zero_hit_rules"),
                "disabled": s.get("disabled_rules"),
                "complete": dq.get("complete", True),
            }
        else:
            p["access"] = state

        state, comp = _section(run, "compliance")
        if state == "ok":
            s = comp.get("summary") or {}
            p["compliance"] = {"passed": s.get("passed"), "failed": s.get("failed"),
                               "unverifiable": s.get("unverifiable"),
                               "conformant": comp.get("conformant"),
                               "profile": (comp.get("profile") or {}).get("id") or run.get("profile")}
        else:
            p["compliance"] = state

        state, gw = _section(run, "gateways")
        if state == "ok":
            sev: dict[str, int] = {}
            for f in gw.get("findings") or []:
                sev[str(f.get("severity"))] = sev.get(str(f.get("severity")), 0) + 1
            p["gateways"] = {"findings": sum(sev.values()), "by_severity": sev,
                             "not_reached": sum(1 for f in gw.get("findings") or []
                                                if f.get("kind") == "not-read")}
        else:
            p["gateways"] = state

        state, ch = _section(run, "changed")
        if state == "ok" and not ch.get("first_run"):
            s = ch.get("summary") or {}
            p["changes"] = {"changed": sum(int(s.get(k) or 0) for k in REAL_CHANGE_KEYS),
                            "could_not_compare": int(s.get("scope_unverifiable") or 0)}
        elif state == "ok":
            p["changes"] = "first-run"
        else:
            p["changes"] = state
        points.append(p)
    return points


def snapshot_points(snapshots: list[dict[str, Any]], package: str | None = None) -> list[dict[str, Any]]:
    """Rows from snapshot.list_snapshots(), oldest first."""
    out = []
    for s in sorted(snapshots, key=lambda x: str(x.get("taken_at") or "")):
        if package and s.get("package") != package:
            continue
        out.append({"id": s.get("id"), "at": s.get("taken_at"),
                    "rules": s.get("access_rules"), "nat_rules": s.get("nat_rules"),
                    # None when no rule reported a count - not zero.
                    "total_hits": s.get("total_hits"),
                    "zero_hit_rules": s.get("zero_hit_rules")})
    return out


def health_points(baselines: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Full baseline documents (health.load_baseline), oldest first."""
    out = []
    for b in sorted(baselines, key=lambda x: str(x.get("taken_at") or "")):
        findings = b.get("findings") if isinstance(b.get("findings"), list) else []
        sev: dict[str, int] = {}
        for f in findings:
            sev[str(f.get("severity"))] = sev.get(str(f.get("severity")), 0) + 1
        out.append({"id": b.get("id"), "at": b.get("taken_at"),
                    "gateways_read": (b.get("summary") or {}).get("gateways_read"),
                    "findings": len(findings), "by_severity": sev,
                    "not_reached": sum(1 for f in findings if f.get("kind") == "not-read")})
    return out


NOTES = [
    "Every point is a review, snapshot or health reading that was actually taken. "
    "Nothing between two points is known, and none is drawn.",
    "A section that was not requested has no point; one that failed is marked "
    "'failed', never counted as zero.",
]
