"""Credential management endpoints.

These are the *only* mutating routes in the application — every other
route is a GET.  They let the operator save, test and delete Check Point
Management and Gaia API credentials through the web UI instead of
editing ``.env`` by hand.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..config import settings
from .. import credential_store
from ..runtime import cp

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/credentials", tags=["credentials"])


# ── request / response models ───────────────────────────────────────

# Every field defaults to None, and None means exactly one thing: "the client
# did not mention this". No value-typed default appears here, because a
# value-typed default cannot say that - it arrives at the endpoint looking
# identical to a deliberate choice and is then written over what was saved.
#
# This cost us the same bug twice.
#
#   v4.31  `password: str = ""`. The Settings form leaves the password blank to
#          mean "keep the saved one" and drops the key; Pydantic put "" back,
#          and pressing Save after changing a timeout wiped the secret.
#
#   v4.37  `mgmt: str = ""`. The sign-in form's "use these for reads too" box
#          posts a two-field save. `mgmt` was absent, Pydantic put "" back, and
#          the empty string was written to the store and to settings. Because
#          `auth.configured()` is `mgmt and user`, the application then decided
#          nothing was configured, entered SETUP MODE, and stopped asking
#          anyone to sign in - while the header still read "Connected".
#          Clearing a cookie produced no sign-in form because there was no
#          longer, as far as it knew, anybody to check against.
#
# So the rule is now the model's, not each field's: absent is absent. What a
# save actually persists is assembled by _record() below.
class CheckPointCreds(BaseModel):
    mgmt: str | None = None
    user: str | None = None
    password: str | None = None
    domain: str | None = None
    verify_ssl: bool | None = None
    timeout: float | None = None
    min_request_interval: float | None = None
    rate_limit_retries: int | None = None
    rate_limit_base_delay: float | None = None
    cache_ttl: int | None = None

class GaiaCreds(BaseModel):
    enabled: bool | None = None
    user: str | None = None
    password: str | None = None
    hosts: str | None = None
    verify_ssl: bool | None = None
    timeout: float | None = None

class SaveRequest(BaseModel):
    type: str          # "checkpoint" | "gaia"
    checkpoint: CheckPointCreds | None = None
    gaia: GaiaCreds | None = None

class TestRequest(BaseModel):
    type: str
    checkpoint: CheckPointCreds | None = None
    gaia: GaiaCreds | None = None

class DeleteRequest(BaseModel):
    type: str


# ── helpers ─────────────────────────────────────────────────────────

# The values a record falls back to when neither the client nor the store has
# an opinion. They live here rather than on the model so that "what this field
# defaults to" and "did the client send this field" stop being the same
# question - which is what made the two bugs above possible.
DEFAULTS: dict[str, dict[str, Any]] = {
    "checkpoint": {"mgmt": "", "user": "", "password": "", "domain": "",
                   "verify_ssl": False, "timeout": 90.0,
                   "min_request_interval": 0.55, "rate_limit_retries": 4,
                   "rate_limit_base_delay": 2.0, "cache_ttl": 300},
    "gaia": {"enabled": False, "user": "", "password": "", "hosts": "",
             "verify_ssl": False, "timeout": 30.0},
}

# Fields where an empty string cannot be a setting anybody chose. There is no
# such thing as a Management Server with no address or an account with no name,
# so a blank one can only mean the value went missing on the way here.
# Credentials are cleared through DELETE, which has its own explicit path.
NEVER_BLANK = ("mgmt", "user")


def _supplied(data: dict[str, Any]) -> dict[str, Any]:
    """Only the keys that carry a real answer.

    Drops ``None`` (not supplied) and drops a blank where blank is meaningless
    (see NEVER_BLANK). Everything else - including an empty password - is a
    value the caller meant, and is kept so it stays clearable.
    """
    return {k: v for k, v in data.items()
            if v is not None and not (k in NEVER_BLANK and v == "")}


def _record(cred_type: str, supplied: dict[str, Any]) -> dict[str, Any]:
    """What to persist: defaults, overlaid with the store, overlaid with *supplied*.

    A save carries forward everything the client did not mention. A form that
    sends two fields therefore changes two fields, which is the whole point:
    before this, it replaced the record.
    """
    record = dict(DEFAULTS.get(cred_type, {}))
    record.update(_supplied(credential_store.load(cred_type) or {}))
    record.update(_supplied(supplied))
    return record


def address_source() -> str:
    """Where the Management Server address now in ``settings`` came from.

    ``"saved"`` when a stored record supplied it, ``"env"`` otherwise. The
    distinction is not cosmetic: a stored record overrides .env at startup, so
    an address that is wrong in the store cannot be corrected by editing .env,
    and somebody who does not know that will edit .env repeatedly and watch
    nothing change.

    This lives here because this module is what applies a stored record over
    the settings. Callers use it to tell a person what to do; nothing branches
    on it.
    """
    return "saved" if (credential_store.load("checkpoint") or {}).get("mgmt") else "env"


def _apply_checkpoint(data: dict[str, Any]) -> None:
    """Push decrypted Check Point values into the running settings.

    A missing value never reaches ``settings``: an absent key, an explicit
    ``None``, and a blank where blank is meaningless all mean "leave the
    running value alone". That last one matters on startup - a store written by
    an older build still holds ``mgmt: ""``, and applying it would blank the
    address that came from .env and switch authentication off again.
    """
    data = _supplied(data)
    settings.checkpoint_mgmt = data.get("mgmt", settings.checkpoint_mgmt)
    settings.checkpoint_user = data.get("user", settings.checkpoint_user)
    settings.checkpoint_password = data.get("password", settings.checkpoint_password)
    settings.checkpoint_domain = data.get("domain", settings.checkpoint_domain)
    settings.checkpoint_verify_ssl = data.get("verify_ssl", settings.checkpoint_verify_ssl)
    settings.checkpoint_timeout = data.get("timeout", settings.checkpoint_timeout)
    settings.checkpoint_min_request_interval = data.get("min_request_interval", settings.checkpoint_min_request_interval)
    settings.checkpoint_rate_limit_retries = data.get("rate_limit_retries", settings.checkpoint_rate_limit_retries)
    settings.checkpoint_rate_limit_base_delay = data.get("rate_limit_base_delay", settings.checkpoint_rate_limit_base_delay)
    settings.checkpoint_cache_ttl = data.get("cache_ttl", settings.checkpoint_cache_ttl)


def _apply_gaia(data: dict[str, Any]) -> None:
    """Push decrypted Gaia values into the running settings."""
    data = _supplied(data)
    settings.gaia_enabled = data.get("enabled", settings.gaia_enabled)
    settings.gaia_user = data.get("user", settings.gaia_user)
    settings.gaia_password = data.get("password", settings.gaia_password)
    settings.gaia_hosts = data.get("hosts", settings.gaia_hosts)
    settings.gaia_verify_ssl = data.get("verify_ssl", settings.gaia_verify_ssl)
    settings.gaia_timeout = data.get("timeout", settings.gaia_timeout)


def load_credentials_on_startup() -> None:
    """Restore persisted credentials into the running settings.

    Called from the application lifespan, not at import time. Importing a
    module should not read and decrypt a secret from disk - that happened on
    every ``import app.main``, including during test collection.
    """
    cp_data = credential_store.load("checkpoint")
    if cp_data:
        _apply_checkpoint(cp_data)
        log.info("Restored Check Point credentials from encrypted store")
    gaia_data = credential_store.load("gaia")
    if gaia_data:
        _apply_gaia(gaia_data)
        log.info("Restored Gaia credentials from encrypted store")


def _password_for_test(cred_type: str, supplied: str | None,
                       matches_stored_target: bool) -> str:
    """Password to use for a connectivity test.

    The Settings form leaves the password blank once credentials are saved, so
    a test pressed after a page reload would otherwise always authenticate with
    "" and report a failure that says nothing about the saved credentials.

    Falling back to the stored secret is only safe when the request targets the
    host that secret was stored for. This endpoint accepts an arbitrary target
    URL, so without that check an unauthenticated caller could point it at a
    server they control and have this process post the saved password to it.
    """
    if supplied:
        return supplied
    if not matches_stored_target:
        return supplied or ""
    stored = credential_store.load(cred_type) or {}
    return stored.get("password", "") or ""


# ── endpoints ───────────────────────────────────────────────────────

@router.get("/status")
async def credential_status():
    """Return configuration state for each credential group.

    Never returns actual passwords — only booleans.
    """
    cp_data = credential_store.load("checkpoint")
    gaia_data = credential_store.load("gaia")
    # The Settings form is populated from this, so report the address and
    # account actually in use rather than a blank. A record written before the
    # v4.38 fix can hold `mgmt: ""`; that value is now ignored everywhere else,
    # and showing it here would invite the operator to press Save on a form
    # that has lost the field.
    effective_mgmt = (cp_data.get("mgmt") if cp_data else "") or settings.checkpoint_mgmt
    effective_user = (cp_data.get("user") if cp_data else "") or settings.checkpoint_user
    return {
        "checkpoint": {
            "configured": cp_data is not None,
            "mgmt": effective_mgmt if cp_data else "",
            "user": effective_user if cp_data else "",
            "domain": cp_data.get("domain", "") if cp_data else "",
            "verify_ssl": cp_data.get("verify_ssl", False) if cp_data else False,
            "timeout": cp_data.get("timeout", 90.0) if cp_data else 90.0,
            "min_request_interval": cp_data.get("min_request_interval", 0.55) if cp_data else 0.55,
            "rate_limit_retries": cp_data.get("rate_limit_retries", 4) if cp_data else 4,
            "rate_limit_base_delay": cp_data.get("rate_limit_base_delay", 2.0) if cp_data else 2.0,
            "cache_ttl": cp_data.get("cache_ttl", 300) if cp_data else 300,
            "connected": cp is not None and cp.sid is not None,
        },
        "gaia": {
            "configured": gaia_data is not None,
            "enabled": gaia_data.get("enabled", False) if gaia_data else False,
            "user": gaia_data.get("user", "") if gaia_data else "",
            "hosts": gaia_data.get("hosts", "") if gaia_data else "",
            "verify_ssl": gaia_data.get("verify_ssl", False) if gaia_data else False,
            "timeout": gaia_data.get("timeout", 30.0) if gaia_data else 30.0,
        },
    }


@router.post("")
async def save_credentials(req: SaveRequest):
    """Encrypt and persist credentials, then apply to running config."""
    if req.type == "checkpoint":
        if not req.checkpoint:
            raise HTTPException(400, "checkpoint data required")
        data = _record("checkpoint", req.checkpoint.model_dump())
        credential_store.save("checkpoint", data)
        _apply_checkpoint(data)
        # Re-initialize the client to apply new IP, timeout and SSL settings
        try:
            await cp.close()
        except Exception:
            pass
        cp.base_url = settings.checkpoint_mgmt.rstrip("/")
        cp.client = httpx.AsyncClient(
            verify=settings.checkpoint_verify_ssl,
            timeout=settings.checkpoint_timeout,
            headers={"Content-Type": "application/json"}
        )
        cp.sid = None
        return {"status": "saved", "type": "checkpoint"}

    elif req.type == "gaia":
        if not req.gaia:
            raise HTTPException(400, "gaia data required")
        data = _record("gaia", req.gaia.model_dump())
        credential_store.save("gaia", data)
        _apply_gaia(data)
        return {"status": "saved", "type": "gaia"}

    raise HTTPException(400, f"Unknown type: {req.type}")


@router.post("/test")
async def test_credentials(req: TestRequest):
    """Try a login → logout cycle with the supplied credentials.

    Does **not** persist anything — only validates connectivity.
    """
    if req.type == "checkpoint":
        if not req.checkpoint:
            raise HTTPException(400, "checkpoint data required")
        d = req.checkpoint.model_dump()
        base = (d.get("mgmt") or "").rstrip("/")
        stored_cp = credential_store.load("checkpoint") or {}
        same_target = bool(base) and base == str(stored_cp.get("mgmt", "")).rstrip("/")
        password = _password_for_test("checkpoint", d.get("password"), same_target)
        payload = {"user": d.get("user") or "", "password": password}
        if d.get("domain"):
            payload["domain"] = d["domain"]
        try:
            async with httpx.AsyncClient(
                verify=bool(d.get("verify_ssl")),
                timeout=d.get("timeout") or 30,
            ) as client:
                r = await client.post(f"{base}/web_api/login", json=payload)
                try:
                    body = r.json()
                except Exception:
                    return {"success": False, "message": f"Invalid response from server (Status: {r.status_code})"}
                if r.is_error:
                    return {"success": False, "message": body.get("message", str(body))}
                sid = body.get("sid")
                # Same keys as api/meta.py: a Check Point login returns
                # `api-server-version`, not `api-version`. Reading the wrong
                # one produced an empty string, which the header rendered as
                # "Connected - API ?".
                api_version = (body.get("api-server-version")
                               or body.get("web-api-version")
                               or body.get("api-version", ""))
                # logout immediately
                if sid:
                    try:
                        await client.post(
                            f"{base}/web_api/logout", json={},
                            headers={"X-chkp-sid": sid},
                        )
                    except Exception:
                        pass
                return {
                    "success": True,
                    "message": f"Connected to {base}",
                    "api_version": api_version,
                    "uid": body.get("uid", ""),
                }
        except httpx.ConnectError as exc:
            return {"success": False, "message": f"Connection failed: {exc}"}
        except httpx.TimeoutException:
            return {"success": False, "message": f"Timeout connecting to {base}"}
        except Exception as exc:
            return {"success": False, "message": str(exc)}

    elif req.type == "gaia":
        if not req.gaia:
            raise HTTPException(400, "gaia data required")
        d = req.gaia.model_dump()
        hosts = [h.strip() for h in (d.get("hosts") or "").split(",") if h.strip()]
        if not hosts:
            return {"success": False, "message": "No gateway hosts specified"}
        stored_gaia = credential_store.load("gaia") or {}
        stored_hosts = {h.strip() for h in str(stored_gaia.get("hosts", "")).split(",") if h.strip()}
        same_target = bool(stored_hosts) and set(hosts).issubset(stored_hosts)
        gaia_password = _password_for_test("gaia", d.get("password"), same_target)
        results = []
        for host in hosts[:3]:  # test first 3
            url = f"https://{host}/gaia_api/login"
            try:
                async with httpx.AsyncClient(
                    verify=bool(d.get("verify_ssl")),
                    timeout=d.get("timeout") or 15,
                ) as client:
                    r = await client.post(url, json={
                        "user": d.get("user") or "",
                        "password": gaia_password,
                    })
                    try:
                        body = r.json()
                    except Exception:
                        results.append({"host": host, "ok": False, "msg": f"Invalid response (Status: {r.status_code})"})
                        continue
                    if r.is_error:
                        results.append({"host": host, "ok": False,
                                        "msg": body.get("message", str(body))})
                    else:
                        sid = body.get("sid")
                        if sid:
                            try:
                                await client.post(
                                    f"https://{host}/gaia_api/logout",
                                    json={}, headers={"X-chkp-sid": sid},
                                )
                            except Exception:
                                pass
                        results.append({"host": host, "ok": True, "msg": "OK"})
            except Exception as exc:
                results.append({"host": host, "ok": False, "msg": str(exc)})
        all_ok = all(r["ok"] for r in results)
        return {
            "success": all_ok,
            "message": "All gateways OK" if all_ok else "Some gateways failed",
            "details": results,
        }

    raise HTTPException(400, f"Unknown type: {req.type}")


@router.delete("")
async def delete_credentials(req: DeleteRequest):
    """Remove persisted credentials for *type*."""
    if req.type not in ("checkpoint", "gaia"):
        raise HTTPException(400, f"Unknown type: {req.type}")

    existed = credential_store.delete(req.type)

    # Reset running settings to defaults
    if req.type == "checkpoint":
        settings.checkpoint_mgmt = "https://127.0.0.1"
        settings.checkpoint_user = ""
        settings.checkpoint_password = ""
        settings.checkpoint_domain = ""
        if cp.sid:
            try:
                await cp.close()
            except Exception:
                pass
            cp.sid = None
    elif req.type == "gaia":
        settings.gaia_enabled = False
        settings.gaia_user = ""
        settings.gaia_password = ""
        settings.gaia_hosts = ""

    return {"status": "deleted" if existed else "not_found", "type": req.type}
