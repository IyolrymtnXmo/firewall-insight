"""
Gateway health: read state now, keep a baseline, say what moved.

All GET. Saving a baseline writes one JSON file locally - the second and last
write in the codebase, alongside policy snapshots - and the response says
where it went.

The feature is off unless GAIA_ENABLED is set, and asking for it while it is
off is answered with a reason. "I did not look" and "nothing is wrong" are
different sentences, and this is a page people will read for reassurance.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from .. import health as engine
from ..config import settings
from ..gaia import read_all_state
from ..runtime import use_client  # noqa: F401  (kept for symmetry; Gaia has its own client)

router = APIRouter()


def _disabled():
    raise HTTPException(
        status_code=409,
        detail="GAIA_ENABLED is false, so no gateway state was read. This is not "
               "a statement that the gateways are healthy - set GAIA_ENABLED, "
               "GAIA_USER, GAIA_PASSWORD and GAIA_HOSTS in .env to use this page.")


@router.get("/api/health")
async def health(
    baseline: str | None = Query(None, description="baseline id to compare against"),
    save: bool = Query(True, description="store this reading as a new baseline"),
):
    if not settings.gaia_enabled:
        _disabled()

    report = engine.build_health(await read_all_state())
    saved_id = engine.save_baseline(report) if save else None

    result = {**report, "saved_as": saved_id,
              "saved_to": str(engine.BASELINE_DIR / f"{saved_id}.json") if saved_id else None}

    if baseline:
        try:
            previous = engine.load_baseline(baseline)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        result["diff"] = engine.diff_health(previous, report)

    return result


@router.get("/api/health-baselines")
async def health_baselines():
    rows = engine.list_baselines()
    return {"baselines": rows, "count": len(rows),
            "directory": str(engine.BASELINE_DIR)}
