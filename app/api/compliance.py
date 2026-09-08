"""
Compliance runs: evaluate a customer-authored profile against a package.

Two sources are accepted, and the difference matters to the result rather than
just to the plumbing:

  package=X    read the live package now. Access and NAT analyses are available,
               so checks that depend on them can be decided.
  snapshot=ID  evaluate a snapshot captured earlier. Those same checks come back
               `unverifiable`, because a snapshot does not carry the analyses -
               and that is the honest answer, not a pass.

Both routes are GET, like everything else. Running against a live package
captures a snapshot on the way through, so a compliance run is always tied to
a file somebody can re-open and re-evaluate later.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from .. import compliance as engine
from .. import snapshot as store
from ..policy import analyze_nat, analyze_package, package_access_tree
from ..progress import progress_done, progress_set
from ..runtime import cache_get, cache_set, use_client

router = APIRouter()


@router.get("/api/compliance-profiles")
async def compliance_profiles():
    rows = engine.list_profiles()
    return {
        "profiles": rows,
        "count": len(rows),
        "directory": str(engine.PROFILE_DIR),
        "notes": [
            "Profiles are files, not code. Copy one, edit it, and it is yours.",
            "A check with no cited standard still runs; it is reported as a "
            "house rule so nobody mistakes it for a regulatory finding.",
        ],
    }


@router.get("/api/compliance")
async def compliance(
    profile: str = Query(...),
    package: str | None = Query(None),
    snapshot: str | None = Query(None),
    rid: str | None = Query(None),
):
    if not package and not snapshot:
        raise HTTPException(
            status_code=400,
            detail="Give either package= to evaluate the live policy, or "
                   "snapshot= to evaluate one captured earlier.")

    try:
        loaded = engine.load_profile_by_id(profile)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    if snapshot:
        try:
            captured = store.load_snapshot(snapshot)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        result = engine.evaluate_profile(loaded, captured)
        result["evaluated"] = {"kind": "snapshot", "id": snapshot}
        result["notes"] = result["notes"] + [
            "Evaluated against a stored snapshot. Checks that need the access or "
            "NAT analysis are unverifiable here, because a snapshot does not "
            "carry them - re-run against the live package to decide those.",
        ]
        return result

    async def run(c):
        STEPS = 4
        progress_set(rid, 0, "Loading package and inline layers", STEPS)
        tree = await package_access_tree(c, package, hydrate=True, rid=rid)

        progress_set(rid, 1, "Reading the NAT rulebase", STEPS)
        nat_payload = cache_get(f"nat:{package}")
        if nat_payload is None:
            try:
                nat_payload = await c.show_nat_rulebase(package)
                cache_set(f"nat:{package}", nat_payload)
            except Exception:                                     # noqa: BLE001
                nat_payload = None

        progress_set(rid, 2, "Analysing the rulebase", STEPS)
        analysis = await analyze_package(c, package)
        try:
            nat_analysis = await analyze_nat(c, package)
        except Exception:                                         # noqa: BLE001
            nat_analysis = None

        progress_set(rid, 3, "Evaluating the profile", STEPS)
        captured = store.build_snapshot(tree, nat_payload, package)
        sid = store.save_snapshot(captured)
        result = engine.evaluate_profile(loaded, captured, analysis, nat_analysis)
        result["evaluated"] = {"kind": "live", "package": package, "snapshot_id": sid}
        result["data_quality"] = (analysis or {}).get("data_quality")
        result["notes"] = result["notes"] + [
            f"A snapshot of this run was saved as {sid}, so the same evidence can "
            "be re-evaluated against a different profile later.",
        ]
        progress_done(rid, "Compliance run complete")
        return result

    return await use_client(run)
