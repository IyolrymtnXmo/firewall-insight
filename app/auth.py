"""
Who is allowed to use this application.

RISK-01, closed. Until now anyone who could reach the port could read the whole
estate's policy, save credentials, and - once schedules existed - point the
application at a server of their choosing. On a tool a team reaches over the
LAN that is not a risk to note in a document; it is the front door left open.

WHY CHECK POINT CREDENTIALS
There is no second password to invent, and authorisation lands where it
belongs: if you may read the policy in SmartConsole, you may read it here. The
cost is stated rather than hidden -

    a login form that accepts Check Point administrator credentials looks
    exactly like a phishing page, so a convincing fake on the same LAN
    collects real ones. Serve this over HTTPS and tell people the address.

    failed attempts reach the Management Server, so this application could be
    used to lock an administrator out. `_Attempts` below rate-limits per
    username so it cannot be used that way carelessly - it is not a defence
    against somebody deliberately trying.

WHAT IS NOT STORED
The user's password is used for one login/logout against the Management API and
then dropped. It is never written down, never cached, and never reused: reads
keep going through the service account already configured. The session holds a
username and nothing else, so this file adds no new secret at rest beyond the
key that signs the cookie.

SETUP MODE
With no Management credentials configured, nobody can be validated against
anything, and demanding a login would lock the operator out of the Settings
page they need in order to configure the credentials. So the application says
plainly that it is unauthenticated and lets them in. That is a stated state,
not a silent bypass: `status()` reports it and the UI shows a banner.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_ROOT = Path(__file__).resolve().parent.parent
KEY_FILE = _ROOT / ".session_key"

COOKIE_NAME = "fwi_session"
SESSION_HOURS = 12

# "Keep me signed in". The credentials are the Management Server's, so typing
# them at every visit is both a nuisance and a habit worth not building - the
# more often somebody types an administrator password into a web form, the less
# they look at the address bar first.
#
# The trade is real and belongs in the open: a month-long cookie on a shared
# machine is a month-long window for whoever else uses it. It is opt-in, and
# signing out ends it immediately.
REMEMBER_DAYS = 30

# Rate limiting. Deliberately per-username: the point is not to stop an
# attacker - it is to stop this application from being the thing that locks a
# real administrator out of the Management Server.
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 300


def _key() -> bytes:
    if KEY_FILE.exists():
        return KEY_FILE.read_bytes().strip()
    key = base64.urlsafe_b64encode(secrets.token_bytes(32))
    KEY_FILE.write_bytes(key)
    log.info("Generated a session signing key at %s", KEY_FILE)
    return key


def _sign(payload: bytes) -> str:
    return base64.urlsafe_b64encode(
        hmac.new(_key(), payload, hashlib.sha256).digest()).decode().rstrip("=")


def issue(username: str, hours: int | None = None) -> str:
    """A signed, self-contained session token. No server-side session table.

    Nothing sensitive is inside it - a username and two timestamps - so the
    signature is there to stop somebody writing their own, not to hide it.
    """
    lifetime = (hours if hours is not None else SESSION_HOURS) * 3600
    body = json.dumps({"u": username, "iat": int(time.time()),
                       "exp": int(time.time()) + lifetime},
                      separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(body).decode().rstrip("=") + "." + _sign(body)


def read(token: str | None) -> str | None:
    """The username in *token*, or None if it is absent, forged or expired."""
    if not token or "." not in token:
        return None
    encoded, signature = token.rsplit(".", 1)
    try:
        body = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except Exception:                                             # noqa: BLE001
        return None
    if not hmac.compare_digest(_sign(body), signature):
        return None
    try:
        claims = json.loads(body)
    except json.JSONDecodeError:
        return None
    if int(claims.get("exp", 0)) < time.time():
        return None
    return str(claims.get("u")) or None


class _Attempts:
    """Failed logins per username, so this cannot be a lockout tool."""

    def __init__(self):
        self._failures: dict[str, list[float]] = {}

    def _recent(self, user: str) -> list[float]:
        now = time.time()
        kept = [t for t in self._failures.get(user, []) if now - t < LOCKOUT_SECONDS]
        self._failures[user] = kept
        return kept

    def locked_for(self, user: str) -> int:
        recent = self._recent(user)
        if len(recent) < MAX_ATTEMPTS:
            return 0
        return int(LOCKOUT_SECONDS - (time.time() - min(recent))) + 1

    def record_failure(self, user: str) -> None:
        self._failures.setdefault(user, []).append(time.time())

    def clear(self, user: str) -> None:
        self._failures.pop(user, None)


attempts = _Attempts()


def configured() -> bool:
    """Whether anybody can be validated at all.

    Imported here rather than at module load so a test can point the settings
    somewhere else first.
    """
    from .config import settings
    return bool(settings.checkpoint_mgmt and settings.checkpoint_user)


def status(username: str | None) -> dict[str, Any]:
    return {
        "required": configured(),
        "authenticated": username is not None,
        "user": username,
        "setup_mode": not configured(),
        "note": (
            "Sign in with the Check Point Management API credentials you already "
            "have. They are checked against the Management Server and then "
            "discarded - this application stores no password of its own."
            if configured() else
            "No Management API credentials are configured, so there is nobody to "
            "check a sign-in against. The application is UNAUTHENTICATED until "
            "you configure them on the Settings page."),
    }
