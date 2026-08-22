"""
Firewall Insight - application entry point.

Read-only analysis layer over the Check Point Management API.

Layout:
    app/api/        HTTP routes, one module per product area
    app/policy.py   fetch -> hydrate -> analyse orchestration and caching
    app/runtime.py  shared client, cache and rate-limit-aware error mapping
    app/progress.py live phase reporting for long requests
    app/*.py        pure analysis modules (resolver, analyzer, traffic, ...)
    app/templates/  index.html
    app/static/     app.css, app.js
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from .api import router
from .runtime import cp
from .version import APP_VERSION


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Log out of the Management API when the server stops.

    This replaces @app.on_event("shutdown"), which FastAPI deprecated. The
    session token is held by the shared client in runtime.py, so closing it
    here is what releases the Management session instead of leaving it to
    time out on the appliance.
    """
    yield
    await cp.close()


app = FastAPI(
    title="Firewall Insight - Check Point Firewall Analysis Platform",
    version=APP_VERSION,
    lifespan=lifespan,
)

app.mount(
    "/static",
    StaticFiles(directory=Path(__file__).resolve().parent / "static"),
    name="static",
)
app.include_router(router)