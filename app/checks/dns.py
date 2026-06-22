"""Ported from backend/src/checks/dns.ts.

MX/A/TXT/DMARC/DKIM + DNSBL/DBL lookups via dnspython, with the same 24h
in-memory cache and 3s per-query timeout from CONFIG. Returns the same
DomainDNSResult shape. Network failures are swallowed exactly as in the TS
(every lookup is best-effort; a failed lookup leaves its field at default).
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

import dns.asyncresolver

from app.config import CONFIG


@dataclass
class DomainDNSResult:
    has_mx: bool
    has_a_fallback: bool
    spf_found: bool
    dmarc_found: bool
    dkim_found: bool
    blacklisted: bool
    domain_blacklisted: bool
    infrastructure_risk: bool
    domain_age_days: int
    cached_at: float
    mx_record: Optional[str] = None
    mx_records: Optional[list[str]] = None
    mx_ip: Optional[str] = None


_cache: dict[str, DomainDNSResult] = {}

DKIM_SELECTORS = [
    "google", "default", "mail", "k1", "s1", "s2", "dkim",
    "selector1", "selector2", "mailjet", "sendgrid", "mimecast",
    "proofpoint", "amazonses",
]


def _now_ms() -> float:
    return time.time() * 1000


async def _resolve(name: str, rdtype: str, timeout_ms: float):
    """Resolve with a per-query lifetime, mirroring withTimeout(ms)."""
    return await dns.asyncresolver.resolve(name, rdtype, lifetime=timeout_ms / 1000)


def _join_txt(rdata) -> str:
    return b"".join(rdata.strings).decode("utf-8", "replace")


def _reverse_ip(ip: str) -> str:
    """Reverse an IPv4 address for DNSBL lookup (e.g. 1.2.3.4 -> 4.3.2.1)."""
    return ".".join(reversed(ip.split(".")))


async def _check_dnsbl(ip: str) -> bool:
    """Check if resolved IP is listed in any DNSBL zone."""
    reversed_ip = _reverse_ip(ip)
    found = False
    for zone in CONFIG["dnsbl"]["zones"]:
        try:
            results = await _resolve(f"{reversed_ip}.{zone}", "A", CONFIG["dns"]["timeoutMs"])
            if len(results) > 0:
                found = True
        except Exception:
            pass
    return found


async def _check_domain_dbl(domain: str) -> bool:
    """Check if domain is listed in Spamhaus DBL (domain block list)."""
    try:
        results = await _resolve(f"{domain}.dbl.spamhaus.org", "A", 2000)
        return any(r.address in ("127.0.1.2", "127.0.1.4", "127.0.1.5") for r in results)
    except Exception:
        return False


async def _check_dkim(domain: str) -> bool:
    """Probe common DKIM selectors."""
    for selector in DKIM_SELECTORS:
        try:
            records = await _resolve(
                f"{selector}._domainkey.{domain}", "TXT", CONFIG["dns"]["timeoutMs"]
            )
            if any(_join_txt(r).startswith("v=DKIM1") for r in records):
                return True
        except Exception:
            pass
    return False


async def check_domain(domain: str) -> DomainDNSResult:
    """Full DNS check for a domain with caching."""
    cached = _cache.get(domain)
    if cached and _now_ms() - cached.cached_at < CONFIG["dns"]["cacheTtlMs"]:
        return cached

    has_mx = False
    mx_record: Optional[str] = None
    mx_records: Optional[list[str]] = None
    has_a_fallback = False
    spf_found = False
    dmarc_found = False
    dkim_found = False
    mx_ip: Optional[str] = None
    blacklisted = False
    domain_blacklisted = False
    domain_age_days = -1

    t = CONFIG["dns"]["timeoutMs"]

    # 2. MX lookup
    try:
        raw_mx = await _resolve(domain, "MX", t)
        records = list(raw_mx)
        if len(records) > 0:
            has_mx = True
            records.sort(key=lambda r: r.preference)
            mx_record = records[0].exchange.to_text(omit_final_dot=True)
            mx_records = [r.exchange.to_text(omit_final_dot=True) for r in records]
    except Exception:
        pass

    # 3. A record fallback if no MX
    if not has_mx:
        try:
            a_records = await _resolve(domain, "A", t)
            has_a_fallback = len(a_records) > 0
        except Exception:
            pass

    # 4. TXT lookup for SPF
    try:
        txt_records = await _resolve(domain, "TXT", t)
        for record in txt_records:
            if _join_txt(record).startswith("v=spf1"):
                spf_found = True
    except Exception:
        pass

    try:
        dmarc_records = await _resolve(f"_dmarc.{domain}", "TXT", t)
        for record in dmarc_records:
            if _join_txt(record).startswith("v=DMARC1"):
                dmarc_found = True
    except Exception:
        pass

    # 5. DKIM probe + DBL check in parallel
    import asyncio

    dkim_result, dbl_result = await asyncio.gather(
        _check_dkim(domain), _check_domain_dbl(domain)
    )
    dkim_found = dkim_result
    domain_blacklisted = dbl_result

    # 6. Resolve MX hostname to IP
    if mx_record:
        try:
            ips = await _resolve(mx_record, "A", t)
            ip_list = list(ips)
            if len(ip_list) > 0:
                mx_ip = ip_list[0].address
        except Exception:
            pass

    # 7. DNSBL check
    if mx_ip:
        try:
            blacklisted = await _check_dnsbl(mx_ip)
        except Exception:
            blacklisted = False

    # 8. WHOIS — derive domain age (best-effort; module may not exist yet)
    try:
        from app.checks.whois import check_whois

        whois_result = await check_whois(domain, t)
        if getattr(whois_result, "creation_date", None):
            domain_age_days = int(
                (time.time() - whois_result.creation_date.timestamp()) // 86400
            )
    except Exception:
        pass

    # 9. Infrastructure risk
    infrastructure_risk = not spf_found and not dmarc_found

    result = DomainDNSResult(
        has_mx=has_mx,
        mx_record=mx_record,
        mx_records=mx_records,
        has_a_fallback=has_a_fallback,
        spf_found=spf_found,
        dmarc_found=dmarc_found,
        dkim_found=dkim_found,
        mx_ip=mx_ip,
        blacklisted=blacklisted,
        domain_blacklisted=domain_blacklisted,
        infrastructure_risk=infrastructure_risk,
        domain_age_days=domain_age_days,
        cached_at=_now_ms(),
    )

    _cache[domain] = result
    return result
