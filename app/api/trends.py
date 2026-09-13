"""Trends over the reviews, snapshots and health readings already stored."""

from __future__ import annotations

from fastapi import APIRouter, Query

from .. import health, snapshot, trends
from ..jobs import store

router = APIRouter()


@router.get("/api/trends")
async def trend_series(package: str | None = Query(None)):
    runs, unreadable = [], []
    for row in store.list_runs():
        if row.get("unreadable"):
            unreadable.append(row["id"])
            continue
        try:
            runs.append(store.load_run(row["id"]))
        except Exception as exc:                                  # noqa: BLE001
            unreadable.append(f"{row['id']}: {exc}")
    baselines = []
    for row in health.list_baselines():
        try:
            baselines.append(health.load_baseline(row["id"]))
        except Exception as exc:                                  # noqa: BLE001
            unreadable.append(f"{row['id']}: {exc}")
    snaps = snapshot.list_snapshots()
    packages = sorted({r.get("package") for r in runs if r.get("package")}
                      | {s.get("package") for s in snaps if s.get("package")})
    return {
        "package": package,
        "packages": packages,
        "reviews": trends.review_points(runs, package),
        "snapshots": trends.snapshot_points(snaps, package),
        "health": trends.health_points(baselines),
        "unreadable": unreadable,
        "notes": trends.NOTES,
    }
