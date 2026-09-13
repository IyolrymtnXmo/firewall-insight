"""
Firewall Insight - application entry point.

Read-only analysis layer over the Check Point Management API.

Layout:
    app/api/        HTTP routes, one module per product area
    app/auth.py     signed session cookie, sign-in rate limit, setup mode
    app/credential_store.py  Fernet-encrypted credentials.enc
    app/policy.py   fetch -> hydrate -> analyse orchestration and caching
    app/runtime.py  shared client, cache and rate-limit-aware error mapping
    app/progress.py live phase reporting for long requests
    app/jobs/       reviews: runner, run store, PDF report, schedule loop
    app/*.py        pure analysis modules (resolver, analyzer, traffic,
                    compliance, snapshot_diff, health, gaia, ...)
    app/templates/  index.html
    app/static/     css/app.css, js/app.js

Every route sits behind require_session() below unless it is in PUBLIC_PATHS.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from . import auth
from .api import router
from .api.credentials import load_credentials_on_startup
from .jobs import schedule as schedules
from .runtime import cp
from .version import APP_VERSION


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Restore saved credentials on start; release the session on stop.

    The shutdown half replaces @app.on_event("shutdown"), which FastAPI
    deprecated. The session token is held by the shared client in runtime.py,
    so closing it here is what releases the Management session instead of
    leaving it to time out on the appliance.

    The startup half used to run as an import-time side effect at the bottom
    of api/credentials.py, which decrypted the credential file during any
    ``import app.main`` - test collection included.
    """
    load_credentials_on_startup()
    async with schedules.running():
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

# Paths reachable without a session.
#
# `/` is among them on purpose: it serves the single page, which then asks
# /api/auth/status and draws the sign-in form. Refusing the page itself would
# leave a browser with nowhere to sign in. Everything the page then asks for is
# behind the gate, so an unauthenticated visitor gets the shell and no data.
PUBLIC_PATHS = {"/", "/health", "/api/auth/status", "/api/auth/login",
                "/api/auth/logout"}


@app.middleware("http")
async def require_session(request: Request, call_next):
    """One gate in front of everything, rather than a decorator per route.

    A decorator is something a new route can forget. This cannot be forgotten:
    a path is reachable without a session only by being named above, and a test
    asserts the list has not grown.
    """
    path = request.url.path
    if (path in PUBLIC_PATHS
            or path.startswith("/static/")
            # With nothing configured there is nobody to check against, and
            # demanding a sign-in would lock the operator out of the page where
            # credentials are entered. Reported as a state, never silent.
            or not auth.configured()
            or auth.read(request.cookies.get(auth.COOKIE_NAME))):
        return await call_next(request)

    return JSONResponse(
        status_code=401,
        content={"detail": "Sign in to use this application. Use the Check Point "
                           "Management API credentials you already have."})
