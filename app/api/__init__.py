"""HTTP routes, one module per area of the product.

Every route that reads policy is a GET. That is deliberate: the application
never changes firewall configuration, and keeping the policy surface free of
mutating verbs makes that property easy to verify rather than something you
have to trust.

Two modules are the exception and are confined on purpose. `credentials.py`
holds POST/DELETE routes that write an encrypted credential file; `jobs.py`
holds POST/PUT/DELETE routes that write a schedule file and a run file. Neither
sends anything to a Management Server or a gateway except the same read-only
`show-*` calls every page issues. tests/test_v413_structure.py enforces that
boundary in both directions.
"""

from fastapi import APIRouter

from . import (access, compliance, credentials, export, health, jobs, meta,
               nat, snapshot, topology, traffic, ui)

router = APIRouter()
for module in (meta, access, nat, traffic, topology, snapshot, compliance,
               health, export, ui, credentials, jobs):
    router.include_router(module.router)
