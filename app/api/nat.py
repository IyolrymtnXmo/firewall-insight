"""NAT rulebase analysis."""

from __future__ import annotations

from fastapi import APIRouter, Query

from ..policy import analyze_nat
from ..runtime import use_client

router = APIRouter()


@router.get("/api/nat-analyze")
async def nat_analyze(package: str = Query(...)):
    return await use_client(lambda c: analyze_nat(c, package))
