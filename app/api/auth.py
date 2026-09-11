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
# Asked rather than looked up: this module must not hold a handle on the
# credential store. It validates a password and drops it, and the test in
# test_v413_structure.py that enforces that bans the store's name here on
# purpose - an import sitting in the file is the beginning of keeping one.
from .credentials import address_source

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/auth", tags=["auth"])


class Login(BaseModel):
    user: str
    password: str
    remember: bool = False


def _unreachable(base: str, reason: str) -> str:
    """Why the sign-in failed, and what can be done about it from here.

    A sign-in is tried against the configured Management Server, so an address
    that is wrong locks everybody out - and the Settings page where it would be
    corrected is behind this same form. Worse, a saved record overrides .env,
    so editing .env does not help either. That is a door that locks with the
    key inside it, and the message should say where the key is.

    The distinction matters to whoever reads this: an address that is simply
    unreachable is a network problem and waiting will fix it, while an address
    that is wrong will never work and has to be cleared from outside.
    """
    saved = address_source() == "saved"
    source = ("the saved credentials, which override .env" if saved else ".env")
    tail = (" Clear it with `python -m tools.reset_credentials --clear "
            "checkpoint` on the machine running this application, and .env "
            "applies again." if saved else
            " Correct it in .env and restart.")
    return (f"Could not reach {base}: {reason}. That address comes from "
            f"{source}. If the server is only temporarily unreachable, waiting "
            f"is enough. If the address itself is wrong, nobody can sign in and "
            f"the Settings page cannot be opened without signing in first."
            + tail)


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
        raise HTTPException(status_code=504, detail=_unreachable(
            base, "it did not answer in time"))
    except Exception as exc:                                      # noqa: BLE001
        raise HTTPException(status_code=502, detail=_unreachable(base, str(exc)))

    auth.attempts.clear(user)
    hours = auth.REMEMBER_DAYS * 24 if body.remember else auth.SESSION_HOURS
    response.set_cookie(
        auth.COOKIE_NAME, auth.issue(user, hours),
        max_age=hours * 3600,
        httponly=True,          # not readable from JavaScript
        samesite="lax",         # not sent on a cross-site POST
        # Not `secure`: this is commonly served over plain HTTP on a LAN, and a
        # cookie the browser refuses to send is an application nobody can sign
        # in to. Put it behind HTTPS and this is the line to change.
    )
    log.info("Signed in: %s (%sh)", user, hours)
    return {"user": user, "expires_in_hours": hours,
            # So the page can offer to stop asking for the same credentials
            # twice: once here and once on the Settings page.
            "reads_configured": bool(settings.checkpoint_password),
            "matches_reads_account": user == settings.checkpoint_user}


@router.post("/logout")
async def logout(response: Response):
    response.delete_cookie(auth.COOKIE_NAME)
    return {"status": "signed out"}
