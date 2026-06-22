"""Ported from the DNSBL logic in backend/src/checks/dns.ts (checkDnsbl).

Reverses an IPv4 address and queries every configured DNSBL zone via dnspython.
Zones are queried concurrently (asyncio.gather ≈ Promise.all); any A-record hit
in any zone means listed. Each per-zone failure swallows to False, matching the
TS try/catch → false.
"""
from __future__ import annotations

import asyncio

import dns.asyncresolver

from app.config import CONFIG


def reverse_ip(ip: str) -> str:
    """Reverse an IPv4 address for DNSBL lookup (e.g. 1.2.3.4 -> 4.3.2.1)."""
    return ".".join(reversed(ip.split(".")))


async def _check_zone(reversed_ip: str, zone: str) -> bool:
    try:
        results = await dns.asyncresolver.resolve(
            f"{reversed_ip}.{zone}", "A", lifetime=CONFIG["dns"]["timeoutMs"] / 1000
        )
        return len(results) > 0
    except Exception:
        return False


async def check_dnsbl(ip: str) -> bool:
    """True if the IP is listed in any configured DNSBL zone."""
    reversed_ip = reverse_ip(ip)
    results = await asyncio.gather(
        *(_check_zone(reversed_ip, zone) for zone in CONFIG["dnsbl"]["zones"])
    )
    return any(results)
