"""HTTP routes, one module per area of the product.

Every route that reads policy is a GET. That is deliberate: the application
never changes firewall configuration, and keeping the policy surface free of
mutating verbs makes that property easy to verify rather than something you
have to trust.

`credentials.py` is the single exception and is confined on purpose - it holds
the only POST/DELETE routes, and they write to a local encrypted credential
file, never to a Management Server or a gateway. tests/test_v413_structure.py
enforces that boundary in both directions.
"""

from fastapi import APIRouter

from . import (access, compliance, credentials, export, health, meta, nat,
               snapshot, topology, traffic, ui)

router = APIRouter()
for module in (meta, access, nat, traffic, topology, snapshot, compliance,
               health, export, ui, credentials):
    router.include_router(module.router)
