"""Encrypted credential storage using Fernet (AES-128-CBC + HMAC-SHA256).

Credentials are encrypted and persisted to ``credentials.enc`` so they
survive server restarts.  The encryption key is auto-generated on first
use and stored in ``.credential_key`` (must be gitignored).

The store is purely a persistence layer — it does **not** import or
modify :pymod:`app.config` directly.  The API layer is responsible for
pushing decrypted values into the running ``settings`` singleton.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

log = logging.getLogger(__name__)

_ROOT = Path(__file__).resolve().parent.parent  # project root
KEY_FILE = _ROOT / ".credential_key"
ENC_FILE = _ROOT / "credentials.enc"


# ── key management ──────────────────────────────────────────────────

def _ensure_key() -> bytes:
    """Return the Fernet key, generating one if it does not exist."""
    if KEY_FILE.exists():
        return KEY_FILE.read_bytes().strip()
    key = Fernet.generate_key()
    KEY_FILE.write_bytes(key)
    log.info("Generated new credential encryption key → %s", KEY_FILE)
    return key


def _fernet() -> Fernet:
    return Fernet(_ensure_key())


# ── public API ──────────────────────────────────────────────────────

def save(cred_type: str, data: dict[str, Any]) -> None:
    """Encrypt *data* under *cred_type* and persist to disk.

    ``cred_type`` is ``"checkpoint"`` or ``"gaia"``.  Existing entries
    for *other* types are preserved.
    """
    all_creds = load_all()
    all_creds[cred_type] = data
    payload = json.dumps(all_creds, ensure_ascii=False).encode()
    ENC_FILE.write_bytes(_fernet().encrypt(payload))
    log.info("Saved encrypted credentials for [%s]", cred_type)


def load_all() -> dict[str, dict[str, Any]]:
    """Decrypt and return the full credential map, or ``{}``."""
    if not ENC_FILE.exists():
        return {}
    try:
        raw = _fernet().decrypt(ENC_FILE.read_bytes())
        return json.loads(raw)
    except (InvalidToken, json.JSONDecodeError):
        log.warning("credentials.enc is corrupt or key mismatch — ignoring")
        return {}


def load(cred_type: str) -> dict[str, Any] | None:
    """Return credentials for *cred_type*, or ``None``."""
    return load_all().get(cred_type)


def delete(cred_type: str) -> bool:
    """Remove *cred_type* from the store.  Returns ``True`` if it existed."""
    all_creds = load_all()
    if cred_type not in all_creds:
        return False
    del all_creds[cred_type]
    if all_creds:
        payload = json.dumps(all_creds, ensure_ascii=False).encode()
        ENC_FILE.write_bytes(_fernet().encrypt(payload))
    else:
        ENC_FILE.unlink(missing_ok=True)
    log.info("Deleted credentials for [%s]", cred_type)
    return True


def is_configured(cred_type: str) -> bool:
    """Check whether *cred_type* has saved credentials."""
    return load(cred_type) is not None
