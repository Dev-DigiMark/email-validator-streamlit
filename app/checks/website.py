"""Ported from backend/src/checks/website.ts.

Coarse "does this domain serve a live website" scoring signal via httpx.
Same apex→www→http fallback ladder, same 24h cache, same indicatesWebsite rule
(any status except 404/410 counts; a never-completed request counts as no site).
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

import httpx

from app.config import CONFIG

# Browser-like UA: bot-protection / WAFs (Cloudflare, etc.) often 403 or drop
# requests with no User-Agent, producing false negatives.
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
)


@dataclass
class WebsiteCheckResult:
    has_website: bool
    cached_at: float
    status_code: Optional[int] = None


_cache: dict[str, WebsiteCheckResult] = {}


def _now_ms() -> float:
    return time.time() * 1000


async def _probe(url: str) -> Optional[int]:
    """Single GET probe. Returns the HTTP status code, or None if the request
    never completed (DNS/TCP/TLS failure, timeout). GET (not HEAD) because many
    real servers reject HEAD; we stream and never read the body."""
    timeout = CONFIG["scoringEngine"]["websiteCheck"]["timeoutMs"] / 1000
    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=timeout,
            headers={"User-Agent": USER_AGENT},
        ) as client:
            async with client.stream("GET", url) as res:
                return res.status_code
    except Exception:
        return None


def _indicates_website(status: Optional[int]) -> bool:
    """A status line means a live server answered. Everything except an explicit
    'this resource is gone' (404/410) counts as a real web presence."""
    if status is None:
        return False
    return status != 404 and status != 410


async def check_website(domain: str) -> WebsiteCheckResult:
    if not CONFIG["scoringEngine"]["websiteCheck"]["enabled"]:
        return WebsiteCheckResult(has_website=False, cached_at=_now_ms())

    cached = _cache.get(domain)
    if cached and _now_ms() - cached.cached_at < CONFIG["scoringEngine"]["websiteCheck"]["cacheTtlMs"]:
        return cached

    status = await _probe(f"https://{domain}")

    # Apex gave nothing usable — many real sites only serve on www.
    if not _indicates_website(status) and not domain.startswith("www."):
        www_status = await _probe(f"https://www.{domain}")
        if _indicates_website(www_status):
            status = www_status

    # Both HTTPS probes returned None (network/TLS failure) — try plain HTTP.
    if status is None:
        status = await _probe(f"http://{domain}")
        if status is None and not domain.startswith("www."):
            www_status = await _probe(f"http://www.{domain}")
            if www_status is not None:
                status = www_status

    has_website = _indicates_website(status)
    result = WebsiteCheckResult(
        has_website=has_website,
        status_code=status if status is not None else None,
        cached_at=_now_ms(),
    )
    _cache[domain] = result
    return result
