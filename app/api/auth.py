"""
Sign in, sign out, and say who is signed in.

The login itself is one Management API `login` immediately followed by a
`logout`, made with a throwaway client so it cannot disturb the long-lived
read-only session the rest of the application shares. The supplied password
reaches that call and nothing else - it is not stored, cached or reused.
"""

from __future__ import annotations

import logging

import httpx
from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel

from .. import auth
from ..config import settings

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/auth", tags=["auth"])


class Login(BaseModel):
    user: str
    password: str


@router.get("/status")
async def status(request: Request):
    return auth.status(auth.read(request.cookies.get(auth.COOKIE_NAME)))


@router.post("/login")
async def login(body: Login, response: Response):
    if not auth.configured():
        raise HTTPException(
            status_code=409,
            detail="No Management API credentials are configured, so there is "
                   "nothing to check a sign-in against. Configure them on the "
                   "Settings page first.")

    user = body.user.strip()
    if not user or not body.password:
        raise HTTPException(status_code=400, detail="Enter a username and password.")

    wait = auth.attempts.locked_for(user)
    if wait:
        # Refused here rather than forwarded, so this application cannot be
        # used to lock the account out on the Management Server.
        raise HTTPException(
            status_code=429,
            detail=f"Too many failed sign-ins for '{user}'. Wait {wait}s. "
                   "Attempts are limited here so this application cannot be "
                   "used to lock the account out on the Management Server.")

    base = settings.checkpoint_mgmt.rstrip("/")
    payload = {"user": user, "password": body.password}
    if settings.checkpoint_domain:
        payload["domain"] = settings.checkpoint_domain

    try:
        # A throwaway client: the shared one holds the read-only session every
        # page uses, and a sign-in must not disturb it.
        async with httpx.AsyncClient(verify=settings.checkpoint_verify_ssl,
                                     timeout=settings.checkpoint_timeout) as client:
            r = await client.post(f"{base}/web_api/login", json=payload)
            body_json = r.json() if r.headers.get("content-type", "").startswith(
                "application/json") else {}
            if r.is_error or not body_json.get("sid"):
                auth.attempts.record_failure(user)
                raise HTTPException(
                    status_code=401,
                    detail=body_json.get("message")
                    or "The Management Server did not accept those credentials.")
            # Hand the session straight back. Holding it would mean this
            # application had a second live session per signed-in person.
            try:
                await client.post(f"{base}/web_api/logout", json={},
                                  headers={"X-chkp-sid": body_json["sid"]})
            except Exception:                                     # noqa: BLE001
                pass
    except HTTPException:
        raise
    except httpx.TimeoutException:
        raise HTTPException(status_code=504,
                            detail=f"The Management Server at {base} did not answer.")
    except Exception as exc:                                      # noqa: BLE001
        raise HTTPException(status_code=502,
                            detail=f"Could not reach {base}: {exc}")

    auth.attempts.clear(user)
    response.set_cookie(
        auth.COOKIE_NAME, auth.issue(user),
        max_age=auth.SESSION_HOURS * 3600,
        httponly=True,          # not readable from JavaScript
        samesite="lax",         # not sent on a cross-site POST
        # Not `secure`: this is commonly served over plain HTTP on a LAN, and a
        # cookie the browser refuses to send is an application nobody can sign
        # in to. Put it behind HTTPS and this is the line to change.
    )
    log.info("Signed in: %s", user)
    return {"user": user, "expires_in_hours": auth.SESSION_HOURS}


@router.post("/logout")
async def logout(response: Response):
    response.delete_cookie(auth.COOKIE_NAME)
    return {"status": "signed out"}
