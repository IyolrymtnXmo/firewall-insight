"""
One review run: read the policy, analyse it, store it, and say what moved.

This composes service functions that already exist and already have tests. It
introduces no new analysis and no new Management API command - if a page can
show it today, a run can record it, and if a page reports something as unknown
today, a run records it as unknown too.

Partial failure is a result, not an exception. Gaia being unreachable does not
make the access analysis worthless, and it must not be recorded as "no gateway
findings" either: each section carries its own `ok` and `error`, and the run's
`complete` flag is false when any requested section did not produce an answer.
That is the same distinction the rest of the application makes between "I did
not look" and "nothing is wrong".
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from .. import compliance as compliance_engine
from .. import health as health_engine
from .. import snapshot as snapshot_store
from ..config import settings
from ..policy import analyze_nat, analyze_package, package_access_tree
from ..runtime import cache_get, cache_set
from ..snapshot_diff import diff_snapshots
from ..version import APP_VERSION


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class _Section:
    """A part of a run that can succeed, fail, or not have been asked for."""

    __slots__ = ("requested", "ok", "error", "data")

    def __init__(self, requested: bool):
        self.requested = requested
        self.ok = False
        self.error: str | None = None
        self.data: Any = None

    def done(self, data: Any) -> None:
        self.ok, self.data = True, data

    def failed(self, exc: BaseException) -> None:
        self.ok, self.error = False, str(exc) or exc.__class__.__name__

    def as_dict(self) -> dict[str, Any]:
        return {"requested": self.requested, "ok": self.ok,
                "error": self.error, "data": self.data}


async def run_review(
    c,
    package: str,
    *,
    profile: str | None = None,
    include_health: bool = True,
    compare_previous: bool = True,
    on_step=None,
) -> dict[str, Any]:
    """Run one review of *package* and return everything it found.

    `c` is a Management API client. Nothing here knows whether a person, a
    schedule or Task Scheduler asked for this.

    `on_step(index, total, label)` is called before each phase so a caller can
    report progress; the UI passes the existing progress registry, the CLI
    prints, and a schedule passes nothing.
    """
    started = time.time()
    steps = ["Reading the policy package", "Analysing access and NAT",
             "Storing the snapshot", "Comparing with the previous run",
             "Evaluating the compliance profile", "Reading gateway state"]

    def step(i: int) -> None:
        if on_step:
            on_step(i, len(steps), steps[i])

    access = _Section(True)
    nat = _Section(True)
    stored = _Section(True)
    changed = _Section(compare_previous)
    conformance = _Section(profile is not None)
    gateways = _Section(include_health and bool(settings.gaia_enabled))

    # ---- 1. the policy itself ------------------------------------------
    step(0)
    tree = await package_access_tree(c, package, hydrate=True)

    nat_payload = cache_get(f"nat:{package}")
    if nat_payload is None:
        try:
            nat_payload = await c.show_nat_rulebase(package)
            cache_set(f"nat:{package}", nat_payload)
        except Exception as exc:                                  # noqa: BLE001
            nat_payload = None
            nat.failed(exc)

    # ---- 2. the analyses the pages show --------------------------------
    step(1)
    try:
        access.done(await analyze_package(c, package))
    except Exception as exc:                                      # noqa: BLE001
        access.failed(exc)

    if nat_payload is not None:
        try:
            nat.done(await analyze_nat(c, package))
        except Exception as exc:                                  # noqa: BLE001
            nat.failed(exc)

    # ---- 3. the evidence, on disk --------------------------------------
    # Written before the comparison, so the run that finds a change also
    # leaves behind the snapshot that proves it.
    step(2)
    captured = None
    try:
        captured = snapshot_store.build_snapshot(tree, nat_payload, package)
        sid = snapshot_store.save_snapshot(captured)
        stored.done({"snapshot_id": sid,
                     "taken_at": captured["taken_at"],
                     "summary": captured["summary"]})
    except Exception as exc:                                      # noqa: BLE001
        stored.failed(exc)

    # ---- 4. what moved since last time ---------------------------------
    step(3)
    if compare_previous and captured is not None:
        try:
            previous = _previous_snapshot(package, exclude=stored.data and stored.data["snapshot_id"])
            if previous is None:
                changed.done({"first_run": True,
                              "note": "No earlier snapshot of this package, so "
                                      "there is nothing to compare against yet."})
            else:
                d = diff_snapshots(snapshot_store.load_snapshot(previous["id"]), captured)
                changed.done({"first_run": False,
                              "compared_with": previous["id"],
                              "compared_with_taken_at": previous.get("taken_at"),
                              "identical": d.get("identical"),
                              "summary": d.get("summary"),
                              "warnings": d.get("warnings") or []})
        except Exception as exc:                                  # noqa: BLE001
            changed.failed(exc)

    # ---- 5. the profile, if one was named ------------------------------
    step(4)
    if profile is not None and captured is not None:
        try:
            loaded = compliance_engine.load_profile_by_id(profile)
            conformance.done(compliance_engine.evaluate_profile(
                loaded, captured,
                access.data if access.ok else None,
                nat.data if nat.ok else None))
        except Exception as exc:                                  # noqa: BLE001
            conformance.failed(exc)

    # ---- 6. gateway state ----------------------------------------------
    step(5)
    if gateways.requested:
        try:
            from ..gaia import read_all_state
            report = health_engine.build_health(await read_all_state())
            baseline_id = health_engine.save_baseline(report)
            entry: dict[str, Any] = {"baseline_id": baseline_id,
                                     "findings": report.get("findings") or [],
                                     "gateways": report.get("gateways") or []}
            previous = _previous_baseline(exclude=baseline_id)
            if previous is not None:
                entry["compared_with"] = previous["id"]
                entry["diff"] = health_engine.diff_health(
                    health_engine.load_baseline(previous["id"]), report)
            gateways.done(entry)
        except Exception as exc:                                  # noqa: BLE001
            gateways.failed(exc)

    sections = {"access": access, "nat": nat, "snapshot": stored,
                "changed": changed, "compliance": conformance, "gateways": gateways}
    incomplete = [name for name, sec in sections.items() if sec.requested and not sec.ok]

    return {
        "schema": 1,
        "app_version": APP_VERSION,
        "package": package,
        "started_at": _now(),
        "duration_seconds": round(time.time() - started, 2),
        "profile": profile,
        "complete": not incomplete,
        "incomplete_sections": incomplete,
        "sections": {name: sec.as_dict() for name, sec in sections.items()},
        "notes": [
            "A review run issues the same read-only show-* calls the pages "
            "issue, through the same paced client.",
            "A section that could not be read is reported as not read. It is "
            "never reported as having found nothing.",
        ],
    }


def _previous_snapshot(package: str, exclude: str | None) -> dict[str, Any] | None:
    """The most recent stored snapshot of *package* that is not this run's."""
    rows = [s for s in snapshot_store.list_snapshots()
            if s.get("package") == package and s.get("id") != exclude]
    rows.sort(key=lambda s: str(s.get("taken_at") or ""), reverse=True)
    return rows[0] if rows else None


def _previous_baseline(exclude: str | None) -> dict[str, Any] | None:
    rows = [b for b in health_engine.list_baselines() if b.get("id") != exclude]
    rows.sort(key=lambda b: str(b.get("taken_at") or ""), reverse=True)
    return rows[0] if rows else None
