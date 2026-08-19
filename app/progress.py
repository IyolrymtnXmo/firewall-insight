"""
Live phase reporting for long requests.

The browser makes ONE request for a trace or an analysis and cannot see
server-side phases, so a step indicator driven by a client-side guess would be
decoration that lies. The backend records its phase against a client-supplied
request id and the UI polls for it.
"""

from __future__ import annotations

import time

_progress: dict[str, dict] = {}
PROGRESS_TTL = 600


def progress_set(rid, phase: int, label: str = "", total: int = 0, detail: str = ""):
    """
    Record which phase a long request is in, keyed by a client-supplied id.

    The browser makes one request for a trace or an analysis, so it cannot see
    server-side phases. Without this the UI could only show a fake step list -
    which is the same dishonesty as reporting a partial result as complete.
    """
    if not rid:
        return
    now = time.time()
    for key, value in list(_progress.items()):
        if now - value.get("ts", 0) > PROGRESS_TTL:
            _progress.pop(key, None)
    _progress[rid] = {
        "phase": phase, "label": label, "total": total,
        "detail": detail, "ts": now, "done": False,
    }


def progress_done(rid, label: str = "Complete"):
    if not rid:
        return
    item = _progress.get(rid) or {}
    _progress[rid] = {
        "phase": item.get("total", 0), "label": label,
        "total": item.get("total", 0), "detail": "", "ts": time.time(), "done": True,
    }
