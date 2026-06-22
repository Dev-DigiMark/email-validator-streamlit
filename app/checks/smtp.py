"""Ported from backend/src/checks/smtp.ts — the SMTP state machine line-for-line.

Replaces node:net / node:tls with asyncio.open_connection + ssl. Reproduces:
  - classifySMTPResponse (code + message-keyword classification)
  - the per-port step state machine (banner -> EHLO -> [STARTTLS upgrade] ->
    MAIL FROM -> RCPT TO -> classify)
  - the port ladder 25(plain) -> 2525(starttls) -> 587(starttls) -> 465(implicit-tls)
  - tcp_failed / start_tls_failed fallthrough and the bare-domain port-25 fallback
  - connect/response timeouts and provider inference
All SMTPCheckResult fields and sub_status strings match the TS exactly.
"""
from __future__ import annotations

import asyncio
import re
import ssl
import uuid
from dataclasses import dataclass
from typing import Optional

from app.config import CONFIG

_LINE_RE = re.compile(r"^\d{3}[ -]")
_FULL_RE = re.compile(r"^\d{3}$")
_CONT_RE = re.compile(r"^\d{3}-")


@dataclass
class SMTPCheckResult:
    exists: Optional[bool]
    is_catch_all: bool
    sub_status: str
    should_retry: bool
    smtp_accessible: bool
    smtp_provider: Optional[str] = None
    smtp_response: Optional[str] = None
    smtp_response_code: Optional[int] = None


@dataclass
class _Internal:
    exists: Optional[bool]
    is_catch_all: bool
    sub_status: str
    should_retry: bool
    smtp_accessible: bool
    tcp_failed: bool
    start_tls_failed: bool
    smtp_provider: Optional[str] = None
    smtp_response: Optional[str] = None
    smtp_response_code: Optional[int] = None


def classify_smtp_response(code: int, message: str, _mx_host: str) -> dict:
    """Classify an SMTP RCPT TO response by code + message text."""
    lower = message.lower()
    parser = CONFIG["smtpParser"]

    if code == 250 or code == 251:
        return {"sub_status": "smtp_confirmed", "exists": True}

    if code == 551 or code == 553:
        return {"sub_status": "mailbox_not_found", "exists": False}

    if code == 550:
        is_mailbox_not_found = any(kw in lower for kw in parser["mailboxNotFound"])
        is_mailbox_full = any(kw in lower for kw in parser["mailboxFull"])
        is_mailbox_disabled = any(kw in lower for kw in parser["mailboxDisabled"])
        is_mailbox_suspended = any(kw in lower for kw in parser["mailboxSuspended"])
        is_ip_reputation = any(kw in lower for kw in parser["ipReputation"])
        is_policy = any(kw in lower for kw in parser["policyRejection"])

        if is_mailbox_full:
            return {"sub_status": "mailbox_full", "exists": False}
        if is_mailbox_disabled:
            return {"sub_status": "mailbox_disabled", "exists": False}
        if is_mailbox_suspended:
            return {"sub_status": "mailbox_suspended", "exists": False}
        if is_ip_reputation and not is_mailbox_not_found:
            return {"sub_status": "ip_reputation_block", "exists": None}
        if is_mailbox_not_found and not is_ip_reputation:
            return {"sub_status": "mailbox_not_found", "exists": False}
        if is_policy and not is_mailbox_not_found:
            return {"sub_status": "policy_rejection", "exists": None}
        return {"sub_status": "ambiguous_rejection", "exists": None}

    if code in (421, 450, 451, 452):
        if code == 452 and any(kw in lower for kw in parser["mailboxFull"]):
            return {"sub_status": "mailbox_full", "exists": False}
        return {"sub_status": "greylisted" if code == 421 else "temp_error", "exists": None}

    if code == 503 or code == 504:
        return {"sub_status": "server_error", "exists": None}

    return {"sub_status": "smtp_connection_failed", "exists": None}


# ── Provider domain-map ───────────────────────────────────────────────────────

PROVIDER_DOMAIN_MAP: dict[str, str] = {
    # Google
    "gmail.com": "Google", "googlemail.com": "Google", "google.com": "Google",
    # Yahoo
    "yahoo.com": "Yahoo", "yahoo.co.uk": "Yahoo", "yahoo.fr": "Yahoo",
    "yahoo.de": "Yahoo", "yahoodns.net": "Yahoo",
    # Microsoft
    "outlook.com": "Microsoft", "hotmail.com": "Microsoft", "live.com": "Microsoft",
    "msn.com": "Microsoft", "microsoft.com": "Microsoft",
    # Apple
    "icloud.com": "Apple", "me.com": "Apple", "mac.com": "Apple",
    # AOL
    "aol.com": "AOL", "aim.com": "AOL",
    # Proton
    "protonmail.com": "Proton", "proton.me": "Proton",
    # Zoho
    "zoho.com": "Zoho", "zoho.eu": "Zoho",
    # GMX
    "gmx.com": "GMX", "gmx.net": "GMX", "gmx.de": "GMX",
    # Yandex
    "yandex.com": "Yandex", "yandex.ru": "Yandex", "ya.ru": "Yandex",
}


def _infer_provider_from_mx_host(mx_host: str) -> Optional[str]:
    lower = mx_host.lower()
    for domain, provider in PROVIDER_DOMAIN_MAP.items():
        if lower == domain or lower.endswith("." + domain):
            return provider
    if "google" in lower or "gmail" in lower or "aspmx" in lower:
        return "Google"
    if "yahoo" in lower or "yahoodns" in lower:
        return "Yahoo"
    if "outlook" in lower or "microsoft" in lower:
        return "Microsoft"
    if "icloud" in lower or "apple" in lower:
        return "Apple"
    if "aol" in lower:
        return "AOL"
    if "proton" in lower:
        return "Proton"
    if "zoho" in lower:
        return "Zoho"
    if "gmx" in lower:
        return "GMX"
    if "yandex" in lower:
        return "Yandex"
    return None


def _infer_provider_from_banner(banner: str, from_domain: Optional[str] = None) -> Optional[str]:
    if from_domain:
        return from_domain
    lower = banner.lower()
    if "google" in lower or "gmail" in lower:
        return "Google"
    if "outlook" in lower or "microsoft" in lower:
        return "Microsoft"
    if "yahoo" in lower:
        return "Yahoo"
    if "proton" in lower:
        return "Proton"
    if "mimecast" in lower:
        return "Mimecast"
    if "proofpoint" in lower:
        return "Proofpoint"
    return None


def _tls_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


# ── Per-port SMTP state machine ───────────────────────────────────────────────


async def _do_smtp_check(
    email: str,
    host: str,
    port: int,
    mode: str,
    inferred_provider: Optional[str],
) -> _Internal:
    smtp_cfg = CONFIG["smtp"]
    connect_timeout = smtp_cfg["connectTimeoutMs"] / 1000
    response_timeout = smtp_cfg["responseTimeoutMs"] / 1000
    helo = smtp_cfg["heloDomain"]
    from_addr = smtp_cfg["fromAddress"]

    smtp_accessible = False
    smtp_provider = inferred_provider

    # Connect phase — connect timeout maps to smtp_timeout; TCP/TLS error maps to tcp_failed.
    try:
        if mode == "implicit-tls":
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=_tls_context(), server_hostname=host),
                connect_timeout,
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), connect_timeout
            )
    except asyncio.TimeoutError:
        return _Internal(
            exists=None, is_catch_all=False, sub_status="smtp_timeout",
            should_retry=False, smtp_accessible=False, tcp_failed=False, start_tls_failed=False,
        )
    except (OSError, ssl.SSLError):
        return _Internal(
            exists=None, is_catch_all=False, sub_status="smtp_connection_failed",
            should_retry=False, smtp_accessible=False, tcp_failed=True, start_tls_failed=False,
        )

    buffer = ""
    step = 0
    ehlo_caps: list[str] = []
    upgrading = False

    async def send(data: str) -> None:
        writer.write(data.encode())
        await writer.drain()

    try:
        while True:
            try:
                chunk = await asyncio.wait_for(reader.read(4096), response_timeout)
            except asyncio.TimeoutError:
                return _Internal(
                    exists=None, is_catch_all=False, sub_status="smtp_timeout",
                    should_retry=False, smtp_accessible=smtp_accessible,
                    tcp_failed=False, start_tls_failed=False, smtp_provider=smtp_provider,
                )
            if not chunk:
                # Connection closed before completion — treat as response timeout.
                return _Internal(
                    exists=None, is_catch_all=False, sub_status="smtp_timeout",
                    should_retry=False, smtp_accessible=smtp_accessible,
                    tcp_failed=False, start_tls_failed=False, smtp_provider=smtp_provider,
                )

            buffer += chunk.decode("utf-8", "replace")
            parts = buffer.split("\r\n")
            buffer = parts.pop()

            for line in parts:
                if not line:
                    continue
                if not (_LINE_RE.match(line) or _FULL_RE.match(line)):
                    continue
                is_cont = bool(_CONT_RE.match(line))
                code = int(line[:3])

                if step == 0:
                    # ── 220 banner ──
                    smtp_provider = _infer_provider_from_banner(line, smtp_provider)
                    smtp_accessible = code == 220
                    if code != 220:
                        return _Internal(
                            exists=None, is_catch_all=False, sub_status="smtp_connection_failed",
                            should_retry=False, smtp_accessible=False,
                            tcp_failed=False, start_tls_failed=False, smtp_provider=smtp_provider,
                        )
                    await send(f"EHLO {helo}\r\n")
                    step = 1
                    ehlo_caps = []

                elif step == 1:
                    # ── EHLO response ──
                    if is_cont:
                        if mode == "starttls":
                            ehlo_caps.append(line[4:].lower().strip())
                        continue
                    if mode == "starttls":
                        last_cap = line[4:].lower().strip()
                        has_starttls = last_cap == "starttls" or any(c == "starttls" for c in ehlo_caps)
                        if not has_starttls:
                            return _Internal(
                                exists=None, is_catch_all=False, sub_status="smtp_connection_failed",
                                should_retry=False, smtp_accessible=smtp_accessible,
                                tcp_failed=False, start_tls_failed=True, smtp_provider=smtp_provider,
                            )
                        await send("STARTTLS\r\n")
                        step = 2
                    else:
                        if code >= 400:
                            await send("QUIT\r\n")
                            return _Internal(
                                exists=None, is_catch_all=False, sub_status="smtp_connection_failed",
                                should_retry=False, smtp_accessible=smtp_accessible,
                                tcp_failed=False, start_tls_failed=False, smtp_provider=smtp_provider,
                            )
                        await send(f"MAIL FROM:<{from_addr}>\r\n")
                        step = 4

                elif step == 2:
                    # ── STARTTLS handshake ──
                    if is_cont:
                        continue
                    if code != 220:
                        return _Internal(
                            exists=None, is_catch_all=False, sub_status="smtp_connection_failed",
                            should_retry=False, smtp_accessible=smtp_accessible,
                            tcp_failed=False, start_tls_failed=True, smtp_provider=smtp_provider,
                        )
                    upgrading = True
                    try:
                        await writer.start_tls(_tls_context(), server_hostname=host)
                    except (ssl.SSLError, OSError):
                        return _Internal(
                            exists=None, is_catch_all=False, sub_status="smtp_connection_failed",
                            should_retry=False, smtp_accessible=smtp_accessible,
                            tcp_failed=False, start_tls_failed=True, smtp_provider=smtp_provider,
                        )
                    buffer = ""
                    await send(f"EHLO {helo}\r\n")
                    step = 3
                    break  # drop any leftover pre-TLS bytes

                elif step == 3:
                    # ── Post-TLS EHLO ──
                    if is_cont:
                        continue
                    if code >= 400:
                        await send("QUIT\r\n")
                        return _Internal(
                            exists=None, is_catch_all=False, sub_status="smtp_connection_failed",
                            should_retry=False, smtp_accessible=smtp_accessible,
                            tcp_failed=False, start_tls_failed=False, smtp_provider=smtp_provider,
                        )
                    await send(f"MAIL FROM:<{from_addr}>\r\n")
                    step = 4

                elif step == 4:
                    # ── MAIL FROM response ──
                    if is_cont:
                        continue
                    if code >= 400:
                        await send("QUIT\r\n")
                        return _Internal(
                            exists=None, is_catch_all=False, sub_status="smtp_connection_failed",
                            should_retry=False, smtp_accessible=smtp_accessible,
                            tcp_failed=False, start_tls_failed=False, smtp_provider=smtp_provider,
                        )
                    await send(f"RCPT TO:<{email}>\r\n")
                    step = 5

                elif step == 5:
                    # ── RCPT TO response ──
                    if is_cont:
                        continue
                    await send("QUIT\r\n")
                    cls = classify_smtp_response(code, line, host)
                    should_retry = code in (421, 450, 451, 452)
                    return _Internal(
                        exists=cls["exists"], is_catch_all=False, sub_status=cls["sub_status"],
                        should_retry=should_retry, smtp_accessible=smtp_accessible,
                        tcp_failed=False, start_tls_failed=False, smtp_provider=smtp_provider,
                        smtp_response=line, smtp_response_code=code,
                    )
    except (OSError, ssl.SSLError):
        # Socket error during the conversation: before STARTTLS → tcp_failed,
        # during/after STARTTLS → start_tls_failed (mirrors the TS error handlers).
        if upgrading:
            return _Internal(
                exists=None, is_catch_all=False, sub_status="smtp_connection_failed",
                should_retry=False, smtp_accessible=smtp_accessible,
                tcp_failed=False, start_tls_failed=True, smtp_provider=smtp_provider,
            )
        return _Internal(
            exists=None, is_catch_all=False, sub_status="smtp_connection_failed",
            should_retry=False, smtp_accessible=False, tcp_failed=True, start_tls_failed=False,
            smtp_provider=smtp_provider,
        )
    finally:
        try:
            writer.close()
        except Exception:
            pass


# ── Port ladder ───────────────────────────────────────────────────────────────


def _to_public(res: _Internal, any_accessible: bool) -> SMTPCheckResult:
    return SMTPCheckResult(
        exists=res.exists,
        is_catch_all=res.is_catch_all,
        sub_status=res.sub_status,
        should_retry=res.should_retry,
        smtp_accessible=any_accessible or res.smtp_accessible,
        smtp_provider=res.smtp_provider,
        smtp_response=res.smtp_response,
        smtp_response_code=res.smtp_response_code,
    )


async def check_mailbox(email: str, mx_host: str) -> SMTPCheckResult:
    """Raw SMTP mailbox check using the port ladder.

    Falls through to the next port only on TCP-level failure (tcp_failed) or
    when STARTTLS is not offered (start_tls_failed). Timeouts and protocol
    errors are returned as-is. If all MX-host ports fail at TCP level, retries
    the bare email domain on port 25 (plain) as a final fallback.
    """
    inferred_provider = _infer_provider_from_mx_host(mx_host)
    any_accessible = False

    for entry in CONFIG["smtp"]["ports"]:
        result = await _do_smtp_check(email, mx_host, entry["port"], entry["mode"], inferred_provider)
        if result.smtp_accessible:
            any_accessible = True
        if not result.tcp_failed and not result.start_tls_failed:
            return _to_public(result, any_accessible)
        # TCP-failed or STARTTLS unavailable → try next port

    # All ports on mx_host failed at TCP/TLS level — try bare domain on port 25
    domain = email[email.index("@") + 1:]
    if domain and domain != mx_host:
        fallback = await _do_smtp_check(email, domain, 25, "plain", _infer_provider_from_mx_host(domain))
        if fallback.smtp_accessible:
            any_accessible = True
        if not fallback.tcp_failed and not fallback.start_tls_failed:
            return _to_public(fallback, any_accessible)

    # All attempts exhausted → reserved
    return SMTPCheckResult(
        exists=None,
        is_catch_all=False,
        sub_status="smtp_connection_failed",
        should_retry=False,
        smtp_accessible=any_accessible,
    )


async def check_catch_all(domain: str, mx_host: str) -> bool:
    """Check if a domain is catch-all by probing a random fake address."""
    fake_email = f"verify-{uuid.uuid4().hex[:8]}@{domain}"
    try:
        result = await check_mailbox(fake_email, mx_host)
        return result.exists is True
    except Exception:
        return False
