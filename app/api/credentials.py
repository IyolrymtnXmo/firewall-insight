"""Credential management endpoints.

These are the *only* mutating routes in the application — every other
route is a GET.  They let the operator save, test and delete Check Point
Management and Gaia API credentials through the web UI instead of
editing ``.env`` by hand.
"""

from __future__ import annotations

import asyncio
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

class CheckPointCreds(BaseModel):
    mgmt: str = ""
    user: str = ""
    password: str = ""
    domain: str = ""
    verify_ssl: bool = False
    timeout: float = 90.0
    min_request_interval: float = 0.55
    rate_limit_retries: int = 4
    rate_limit_base_delay: float = 2.0
    cache_ttl: int = 300

class GaiaCreds(BaseModel):
    enabled: bool = False
    user: str = ""
    password: str = ""
    hosts: str = ""
    verify_ssl: bool = False
    timeout: float = 30.0

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

def _apply_checkpoint(data: dict[str, Any]) -> None:
    """Push decrypted Check Point values into the running settings."""
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
    settings.gaia_enabled = data.get("enabled", settings.gaia_enabled)
    settings.gaia_user = data.get("user", settings.gaia_user)
    settings.gaia_password = data.get("password", settings.gaia_password)
    settings.gaia_hosts = data.get("hosts", settings.gaia_hosts)
    settings.gaia_verify_ssl = data.get("verify_ssl", settings.gaia_verify_ssl)
    settings.gaia_timeout = data.get("timeout", settings.gaia_timeout)


def load_credentials_on_startup() -> None:
    """Called once at import-time to restore persisted credentials."""
    cp_data = credential_store.load("checkpoint")
    if cp_data:
        _apply_checkpoint(cp_data)
        log.info("Restored Check Point credentials from encrypted store")
    gaia_data = credential_store.load("gaia")
    if gaia_data:
        _apply_gaia(gaia_data)
        log.info("Restored Gaia credentials from encrypted store")


# ── endpoints ───────────────────────────────────────────────────────

@router.get("/status")
async def credential_status():
    """Return configuration state for each credential group.

    Never returns actual passwords — only booleans.
    """
    cp_data = credential_store.load("checkpoint")
    gaia_data = credential_store.load("gaia")
    return {
        "checkpoint": {
            "configured": cp_data is not None,
            "mgmt": cp_data.get("mgmt", "") if cp_data else "",
            "user": cp_data.get("user", "") if cp_data else "",
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
        data = req.checkpoint.model_dump()
        credential_store.save("checkpoint", data)
        _apply_checkpoint(data)
        # Force re-login with new credentials on next API call
        if cp.sid:
            try:
                await cp.close()
            except Exception:
                pass
            cp.sid = None
        return {"status": "saved", "type": "checkpoint"}

    elif req.type == "gaia":
        if not req.gaia:
            raise HTTPException(400, "gaia data required")
        data = req.gaia.model_dump()
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
        base = d.get("mgmt", "").rstrip("/")
        payload = {"user": d.get("user", ""), "password": d.get("password", "")}
        if d.get("domain"):
            payload["domain"] = d["domain"]
        try:
            async with httpx.AsyncClient(
                verify=d.get("verify_ssl", False),
                timeout=d.get("timeout", 30),
            ) as client:
                r = await client.post(f"{base}/web_api/login", json=payload)
                try:
                    body = r.json()
                except Exception:
                    return {"success": False, "message": f"Invalid response from server (Status: {r.status_code})"}
                if r.is_error:
                    return {"success": False, "message": body.get("message", str(body))}
                sid = body.get("sid")
                api_version = body.get("api-version", "")
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
        hosts = [h.strip() for h in d.get("hosts", "").split(",") if h.strip()]
        if not hosts:
            return {"success": False, "message": "No gateway hosts specified"}
        results = []
        for host in hosts[:3]:  # test first 3
            url = f"https://{host}/gaia_api/login"
            try:
                async with httpx.AsyncClient(
                    verify=d.get("verify_ssl", False),
                    timeout=d.get("timeout", 15),
                ) as client:
                    r = await client.post(url, json={
                        "user": d.get("user", ""),
                        "password": d.get("password", ""),
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


# Auto-load on import
load_credentials_on_startup()
