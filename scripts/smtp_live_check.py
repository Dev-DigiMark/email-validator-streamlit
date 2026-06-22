"""Guarded live SMTP check — verifies one known-good and one known-bad mailbox.

Skipped unless SMTP_LIVE=1, because it requires outbound TCP port 25 (and the
STARTTLS/implicit-TLS ladder ports) to be reachable from this host. Residential
ISPs almost always block port 25, so run this on a port-25-capable network.

Usage:
    SMTP_LIVE=1 python scripts/smtp_live_check.py

Optionally override the targets:
    SMTP_LIVE=1 GOOD_EMAIL=... BAD_EMAIL=... MX_HOST=... python scripts/smtp_live_check.py
"""
from __future__ import annotations

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.checks.dns import check_domain  # noqa: E402
from app.checks.smtp import check_mailbox  # noqa: E402


async def _verify(email: str, mx_host: str | None) -> None:
    if mx_host is None:
        domain = email.split("@", 1)[1]
        dns_result = await check_domain(domain)
        if not dns_result.has_mx or not dns_result.mx_record:
            print(f"  {email}: no MX record for {domain} — cannot probe")
            return
        mx_host = dns_result.mx_record
    result = await check_mailbox(email, mx_host)
    print(
        f"  {email} via {mx_host}: exists={result.exists} "
        f"sub_status={result.sub_status} accessible={result.smtp_accessible} "
        f"code={result.smtp_response_code} resp={result.smtp_response!r}"
    )


async def _main() -> None:
    good = os.environ.get("GOOD_EMAIL", "postmaster@gmail.com")
    bad = os.environ.get("BAD_EMAIL", "definitely-not-a-real-mailbox-xyz123@gmail.com")
    mx_host = os.environ.get("MX_HOST")  # if unset, MX is resolved per-address

    print("Known-good mailbox:")
    await _verify(good, mx_host)
    print("Known-bad mailbox:")
    await _verify(bad, mx_host)


if __name__ == "__main__":
    if os.environ.get("SMTP_LIVE") != "1":
        print("SMTP_LIVE != 1 — skipping live SMTP check (needs outbound port 25).")
        sys.exit(0)
    asyncio.run(_main())
