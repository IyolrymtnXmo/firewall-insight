"""
Process-wide runtime: the Management API client, the response cache and the
lock that keeps heavy calls from overlapping.

Split out of main.py so routers can import it without importing every route,
and so tests can reset it (`cache_clear()`) without touching the app object.
"""

from __future__ import annotations

import asyncio
import time

from fastapi import HTTPException

from .checkpoint import CheckPointAPIError, CheckPointClient, CheckPointRateLimitError
from .config import settings

# One persistent read-only session, reused across requests.
cp = CheckPointClient()

# Serialises the expensive calls so they cannot race each other into the
# Management API rate limit.
heavy_lock = asyncio.Lock()

_cache: dict[str, tuple[float, object]] = {}


def cache_get(key):
    item = _cache.get(key)
    if not item:
        return None
    created, value = item
    if time.time() - created > settings.checkpoint_cache_ttl:
        _cache.pop(key, None)
        return None
    return value


def cache_set(key, value):
    _cache[key] = (time.time(), value)


def cache_pop(key):
    _cache.pop(key, None)


def cache_clear():
    _cache.clear()


async def use_client(fn):
    """
    Run `fn(client)` and translate Management API failures into HTTP status.

    Rate limiting becomes 429 and everything else 502, so the UI can tell
    "slow down" apart from "the server is unreachable".
    """
    try:
        return await fn(cp)
    except CheckPointRateLimitError as e:
        raise HTTPException(
            status_code=429,
            detail=f"{e}. Rate limit retry/backoff was exhausted; wait briefly and retry.",
        )
    except CheckPointAPIError as e:
        raise HTTPException(status_code=502, detail=str(e))
