"""Ported from backend/src/checks/whois.ts.

WHOIS metadata lookup (registrar / country / whois_server / creation_date) via
the python-whois library. Metadata only — never affects score or status. Same
24h cache and same try/except → null-result behaviour as the TS .catch().
The blocking library call is run in a worker thread to keep the async surface.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

import whois as _whois

from app.config import CONFIG  # noqa: F401  (kept for parity with TS module imports)


@dataclass
class WhoisResult:
    registrar: Optional[str]
    country: Optional[str]
    whois_server: Optional[str]
    creation_date: Optional[datetime]


@dataclass
class _CachedWhoisResult:
    result: WhoisResult
    cached_at: float


_CACHE: dict[str, _CachedWhoisResult] = {}
_CACHE_TTL = 24 * 60 * 60 * 1000


def _now_ms() -> float:
    return time.time() * 1000


def _first(value):
    """python-whois fields are sometimes lists; take the first element."""
    if isinstance(value, (list, tuple)):
        return value[0] if value else None
    return value


def _coerce_str(value) -> Optional[str]:
    value = _first(value)
    if value is None:
        return None
    s = str(value).strip()
    return s or None


def _coerce_date(value) -> Optional[datetime]:
    value = _first(value)
    if isinstance(value, datetime):
        return value
    return None


def _lookup(domain: str) -> WhoisResult:
    data = _whois.whois(domain)
    return WhoisResult(
        registrar=_coerce_str(data.get("registrar")),
        country=_coerce_str(data.get("country")),
        whois_server=_coerce_str(data.get("whois_server")),
        creation_date=_coerce_date(data.get("creation_date")),
    )


_NULL_RESULT = WhoisResult(registrar=None, country=None, whois_server=None, creation_date=None)


async def check_whois(domain: str, timeout_ms: int = 3000) -> WhoisResult:
    cached = _CACHE.get(domain)
    if cached and _now_ms() - cached.cached_at < _CACHE_TTL:
        return cached.result

    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(_lookup, domain), timeout=timeout_ms / 1000
        )
        _CACHE[domain] = _CachedWhoisResult(result=result, cached_at=_now_ms())
        return result
    except Exception:
        _CACHE[domain] = _CachedWhoisResult(result=_NULL_RESULT, cached_at=_now_ms())
        return _NULL_RESULT
