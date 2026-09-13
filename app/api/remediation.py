"""The cleanup script: findings turned into commands a person runs.

A GET, and it writes nothing. It reads the same analysis every other page
reads and returns text. The text contains mutating Check Point commands; this
application does not execute them and has no code path that could - see the
module docstring of app/remediation.py and tests/test_v439_features.py.
"""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import PlainTextResponse

from .. import remediation
from ..config import settings
from ..estate_reads import unused_objects
from ..policy import analyze_package, package_access_tree
from ..runtime import use_client
from ..snapshot import build_snapshot

router = APIRouter()


@router.get("/api/remediation-script")
async def remediation_script(
    package: str = Query(...),
    format: str = Query("mgmt_cli"),
    include_zero_hit: bool = Query(False),
    include_disabled: bool = Query(False),
    include_unused_objects: bool = Query(False),
    download: bool = Query(False),
):
    if format not in remediation.FORMATS:
        raise HTTPException(400, f"format must be one of {', '.join(remediation.FORMATS)}")

    async def run(c):
        analysis = await analyze_package(c, package)
        tree = await package_access_tree(c, package, hydrate=True)
        rules = build_snapshot(tree, None, package)["access"]["rules"]
        unused = None
        if include_unused_objects:
            unused, _total, _capped = await unused_objects(c)
        try:
            plan = remediation.build_plan(
                analysis, rules, package=package,
                include_zero_hit=include_zero_hit, include_disabled=include_disabled,
                unused_objects=unused)
        except remediation.RefusedIncomplete as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        script = remediation.render(plan, format, domain=settings.checkpoint_domain)
        return plan, script

    plan, script = await use_client(run)
    if download:
        ext = "sh" if format == "mgmt_cli" else "yml"
        stamp = datetime.now().strftime("%Y%m%d-%H%M")
        return PlainTextResponse(script, headers={
            "Content-Disposition": f'attachment; filename="cleanup-{package}-{stamp}.{ext}"'})
    return {"package": package, "format": format, "plan": plan, "script": script,
            "notes": ["Firewall Insight generated this and did not run it. Read every "
                      "line; nothing is published unless you type PUBLISH, and nothing "
                      "is installed on a gateway."]}
