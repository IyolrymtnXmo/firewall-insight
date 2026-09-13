"""Alert destinations: configure, test, remove.

A mutating module, named in tests/test_v413_structure.py MAY_MUTATE. Its writes
are local - alerts.json and the "alerts" entry of credentials.enc - and its only
outbound traffic is to the destinations configured here: a POST to a webhook
URL, or an SMTP session. It never imports the policy layer or the Management
client, and a test holds it to that.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from ..jobs import alerts, store

router = APIRouter()


class DestinationIn(BaseModel):
    destination: dict[str, Any]
    # Secrets travel beside the destination, never inside the stored config.
    # None and "" both mean "keep the one already saved".
    url: str | None = None
    password: str | None = None


@router.get("/api/alerts")
async def get_alerts():
    return alerts.public_config()


@router.put("/api/alerts/destinations")
async def save_destination(body: DestinationIn):
    try:
        saved = alerts.save_destination(body.destination, url=body.url, password=body.password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"saved": saved, "config": alerts.public_config()}


@router.delete("/api/alerts/destinations/{did}")
async def delete_destination(did: str):
    if not alerts.remove_destination(did):
        raise HTTPException(status_code=404, detail=f"No destination with id '{did}'.")
    return {"status": "deleted", "id": did}


@router.put("/api/alerts/public-url")
async def put_public_url(url: str = Query("")):
    alerts.set_public_url(url)
    return alerts.public_config()


@router.post("/api/alerts/test")
async def test_destination(destination: str = Query(...), run_id: str | None = Query(None)):
    """Send the most recent stored review to one destination, whatever its verdict."""
    runs = [r for r in store.list_runs() if not r.get("unreadable")]
    if run_id:
        target = run_id
    elif runs:
        target = sorted(runs, key=lambda r: str(r.get("started_at") or ""))[-1]["id"]
    else:
        raise HTTPException(status_code=409, detail="There is no stored review to send. "
                                                    "Run one on the Reviews page first.")
    try:
        run = store.load_run(target)
    except Exception as exc:                                      # noqa: BLE001
        raise HTTPException(status_code=404, detail=f"Review {target} could not be read: {exc}")
    results = await alerts.dispatch(run, only=destination, force=True)
    if not results:
        raise HTTPException(status_code=404, detail=f"No destination with id '{destination}'.")
    return {"run_id": target, "results": results}
