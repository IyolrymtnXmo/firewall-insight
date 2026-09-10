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
            "policy_changed": (None if not changed or changed.get("first_run")
                               else (changed.get("identical") is False)),
        })
    out.sort(key=lambda r: str(r.get("started_at") or ""), reverse=True)
    return out
