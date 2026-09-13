"""
Where a review run is kept.

Same shape as `app/snapshot.py` and `app/health.py`: one JSON file per run in a
directory beside them, listed newest first, with `base` overridable so a test
never writes into the operator's real history. Three stores with three
different conventions would be three things to learn.

A run file is small - it holds summaries and the ids of the snapshot and
baseline it produced, not another copy of the rulebase. The evidence already
lives in `snapshots/`; duplicating it here would double the disk cost and,
worse, create a second copy that could drift from the first.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

RUN_DIR = Path(__file__).resolve().parent.parent.parent / "runs"

_SAFE = re.compile(r"[^A-Za-z0-9._-]+")

# The diff counters that mean the policy actually moved. `scope_unverifiable`
# is deliberately absent: a rule whose reach could not be resolved in one of
# the two snapshots is a reason to look, not a change. Kept in step with
# tools/run_review.REAL_CHANGE_KEYS, which a test asserts.
REAL_CHANGE_KEYS = ("added", "removed", "modified", "moved", "scope_changed",
                    "nat_added", "nat_removed", "nat_modified")


def outcome(run: dict[str, Any]) -> dict[str, Any]:
    """What a finished review means, once, for everything that has to say it.

    The CLI's exit code, an alert and a trend all need the same three-way
    answer - look at this / could not tell / nothing moved - and each of the
    earlier places that computed it separately flattened "could not tell" into
    one of the other two at some point. This is the single definition;
    tools/run_review._exit_code is a mapping of `verdict`.
    """
    sections = run.get("sections") or {}

    def sec(name):
        s = sections.get(name) or {}
        if not s.get("requested", True) and not s.get("ok"):
            return "not-requested", {}
        return ("ok", s.get("data") or {}) if s.get("ok") else ("failed", {})

    state, ch = sec("changed")
    counters = ch.get("summary") or {}
    first_run = bool(ch.get("first_run"))
    changes = sum(int(counters.get(k) or 0) for k in REAL_CHANGE_KEYS) if state == "ok" else 0
    changed = state == "ok" and not first_run and changes > 0
    could_not_compare = int(counters.get("scope_unverifiable") or 0) if state == "ok" else 0

    cstate, comp = sec("compliance")
    csum = comp.get("summary") or {}
    if cstate == "ok":
        compliance = "conformant" if comp.get("conformant") else "not-conformant"
    else:
        compliance = cstate

    hstate, gw = sec("gateways")
    findings = gw.get("findings") or []
    high = sum(1 for f in findings if f.get("severity") == "high")
    not_reached = sum(1 for f in findings if f.get("kind") == "not-read")
    health = ("findings" if findings else "clean") if hstate == "ok" else hstate

    incomplete = list(run.get("incomplete_sections") or [])
    if incomplete or could_not_compare:
        undecided = True
    else:
        undecided = False
    if changed or compliance == "not-conformant":
        verdict = "attention"
    elif undecided:
        verdict = "undecided"
    else:
        verdict = "clean"
    # An incomplete read outranks everything: what was not read cannot be
    # called clean, and cannot be the basis for "look at this" either.
    if incomplete:
        verdict = "undecided"

    return {
        "verdict": verdict, "changed": changed, "changes": changes,
        "first_run": first_run, "could_not_compare": could_not_compare,
        "compliance": compliance, "compliance_failed": int(csum.get("failed") or 0),
        "compliance_undecided": int(csum.get("unverifiable") or 0),
        "compliance_profile": (comp.get("profile") or {}).get("name") or run.get("profile"),
        "health": health, "health_findings": len(findings), "health_high": high,
        "not_reached": not_reached, "incomplete": incomplete,
    }


def _dir(base: Path | None = None) -> Path:
    d = base or RUN_DIR
    d.mkdir(parents=True, exist_ok=True)
    return d


def run_id(package: str, started_at: str) -> str:
    """`External-FW-20260910T0900` - sortable, and readable in a file listing."""
    stamp = _SAFE.sub("", str(started_at).replace("-", "").replace(":", ""))[:15]
    return f"{_SAFE.sub('-', package)}-{stamp}"


def save_run(run: dict[str, Any], base: Path | None = None) -> str:
    rid = run.get("id") or run_id(run.get("package", "run"), run.get("started_at", ""))
    run = {**run, "id": rid}
    path = _dir(base) / f"{rid}.json"
    path.write_text(json.dumps(run, indent=2, ensure_ascii=False), encoding="utf-8")
    log.info("Stored review run %s", rid)
    return rid


def load_run(rid: str, base: Path | None = None) -> dict[str, Any]:
    path = _dir(base) / f"{_SAFE.sub('-', rid)}.json"
    if not path.is_file():
        raise FileNotFoundError(f"No stored run with id '{rid}'.")
    return json.loads(path.read_text(encoding="utf-8"))


def list_runs(base: Path | None = None) -> list[dict[str, Any]]:
    """Newest first. A file that cannot be read is named, never skipped silently."""
    out: list[dict[str, Any]] = []
    for path in sorted(_dir(base).glob("*.json")):
        try:
            d = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            out.append({"id": path.stem, "unreadable": str(exc)})
            continue
        sections = d.get("sections") or {}
        changed = ((sections.get("changed") or {}).get("data") or {})
        counters = changed.get("summary") or {}
        out.append({
            "id": d.get("id", path.stem),
            "package": d.get("package"),
            "started_at": d.get("started_at"),
            "duration_seconds": d.get("duration_seconds"),
            "app_version": d.get("app_version"),
            "profile": d.get("profile"),
            "complete": d.get("complete"),
            "incomplete_sections": d.get("incomplete_sections") or [],
            "snapshot_id": ((sections.get("snapshot") or {}).get("data") or {}).get("snapshot_id"),
            # `identical` is false when any of nine counters moved, and one of
            # them - scope_unverifiable - means "could not be compared", not
            # "changed". Reading it as a change is the same flattening the CLI
            # summary and the PDF headline each had; this was the third place.
            "policy_changed": (None if not changed or changed.get("first_run")
                               else any(counters.get(k) for k in REAL_CHANGE_KEYS)),
            "undecided_rules": counters.get("scope_unverifiable", 0),
        })
    out.sort(key=lambda r: str(r.get("started_at") or ""), reverse=True)
    return out
