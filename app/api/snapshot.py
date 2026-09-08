"""
Policy snapshots: capture one, list them, compare two.

Every route here is a GET, like the rest of the application. Capturing does
write a file to the local disk, which is the only write anywhere in this
codebase - so the response says where it went rather than leaving the caller
to discover it. Nothing is sent to the Management Server except the same
`show-*` calls every other page makes; the read-only guarantee is about the
estate, and it is untouched.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from ..policy import package_access_tree
from ..progress import progress_done, progress_set
from ..runtime import cache_get, cache_set, use_client
from .. import snapshot as store          # module, not names: the directory is
                                            # read at call time so a test can
                                            # point it somewhere else
from ..snapshot_diff import diff_snapshots

router = APIRouter()


@router.get("/api/snapshot")
async def take_snapshot(
    package: str = Query(...),
    rid: str | None = Query(None),
):
    async def run(c):
        STEPS = 3
        progress_set(rid, 0, "Loading package and inline layers", STEPS)
        tree = await package_access_tree(c, package, hydrate=True, rid=rid)

        progress_set(rid, 1, "Reading the NAT rulebase", STEPS)
        nat = cache_get(f"nat:{package}")
        nat_error = None
        if nat is None:
            try:
                nat = await c.show_nat_rulebase(package)
                cache_set(f"nat:{package}", nat)
            except Exception as exc:                              # noqa: BLE001
                nat, nat_error = None, str(exc)

        progress_set(rid, 2, "Resolving each rule's reach and writing the file", STEPS)
        snapshot = store.build_snapshot(tree, nat, package)
        sid = store.save_snapshot(snapshot)
        progress_done(rid, "Snapshot captured")

        return {
            "id": sid,
            "package": snapshot["package"],
            "taken_at": snapshot["taken_at"],
            "app_version": snapshot["app_version"],
            "summary": snapshot["summary"],
            "saved_to": str(store.SNAPSHOT_DIR / f"{sid}.json"),
            "nat_error": nat_error,
            "notes": snapshot["notes"] + [
                "This is the only operation in the application that writes to "
                "disk. Nothing was sent to the Management Server but show-* reads.",
            ],
        }
    return await use_client(run)


@router.get("/api/snapshots")
async def snapshots():
    rows = store.list_snapshots()
    return {
        "snapshots": rows,
        "count": len(rows),
        "directory": str(store.SNAPSHOT_DIR),
    }


@router.get("/api/snapshot-diff")
async def snapshot_diff(
    a: str = Query(..., description="older snapshot id"),
    b: str = Query(..., description="newer snapshot id"),
):
    try:
        first, second = store.load_snapshot(a), store.load_snapshot(b)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return diff_snapshots(first, second)
