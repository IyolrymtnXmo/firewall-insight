"""HTTP routes, one module per area of the product.

Every route is a GET. That is deliberate: the application is read-only, and
keeping the router surface free of mutating verbs makes that property easy to
verify rather than something you have to trust.
"""

from fastapi import APIRouter

from . import access, export, meta, nat, topology, traffic, ui

router = APIRouter()
for module in (meta, access, nat, traffic, topology, export, ui):
    router.include_router(module.router)
