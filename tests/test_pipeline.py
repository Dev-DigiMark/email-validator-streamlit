"""End-to-end pipeline test with network checks mocked (the TS inline path).

Drives run_pipeline over a small deterministic batch and asserts the stage
transitions, counts, and final per-email statuses.
"""
import time

import pytest

import app.pipeline.runner as runner
from app.checks.dns import DomainDNSResult
from app.checks.smtp import SMTPCheckResult
from app.checks.website import WebsiteCheckResult
from app.checks.whois import WhoisResult
from app.store.jobs import job_store


def _good_dns() -> DomainDNSResult:
    return DomainDNSResult(
        has_mx=True, has_a_fallback=False, spf_found=True, dmarc_found=True,
        dkim_found=True, blacklisted=False, domain_blacklisted=False,
        infrastructure_risk=False, domain_age_days=400, cached_at=time.time() * 1000,
        mx_record="mx.good.com", mx_records=["mx.good.com"], mx_ip="1.2.3.4",
    )


def _nomx_dns() -> DomainDNSResult:
    return DomainDNSResult(
        has_mx=False, has_a_fallback=False, spf_found=False, dmarc_found=False,
        dkim_found=False, blacklisted=False, domain_blacklisted=False,
        infrastructure_risk=True, domain_age_days=-1, cached_at=time.time() * 1000,
    )


async def _fake_check_domain(domain: str) -> DomainDNSResult:
    if domain == "nomx.com":
        return _nomx_dns()
    return _good_dns()


async def _fake_check_catch_all(domain: str, mx_host: str) -> bool:
    return False


async def _fake_check_mailbox(email: str, mx_host: str) -> SMTPCheckResult:
    if email.startswith("alice"):
        return SMTPCheckResult(
            exists=True, is_catch_all=False, sub_status="smtp_confirmed",
            should_retry=False, smtp_accessible=True, smtp_provider="Google",
            smtp_response="250 OK", smtp_response_code=250,
        )
    # bob → hard bounce
    return SMTPCheckResult(
        exists=False, is_catch_all=False, sub_status="mailbox_not_found",
        should_retry=False, smtp_accessible=True, smtp_provider="Google",
        smtp_response="550 No such user", smtp_response_code=550,
    )


async def _fake_check_website(domain: str) -> WebsiteCheckResult:
    return WebsiteCheckResult(has_website=True, cached_at=time.time() * 1000, status_code=200)


async def _fake_check_whois(domain: str, timeout_ms: int = 3000) -> WhoisResult:
    return WhoisResult(registrar=None, country=None, whois_server=None, creation_date=None)


@pytest.mark.asyncio
async def test_pipeline_end_to_end(monkeypatch):
    monkeypatch.setattr(runner, "check_domain", _fake_check_domain)
    monkeypatch.setattr(runner, "check_catch_all", _fake_check_catch_all)
    monkeypatch.setattr(runner, "check_mailbox", _fake_check_mailbox)
    monkeypatch.setattr(runner, "check_website", _fake_check_website)
    monkeypatch.setattr(runner, "check_whois", _fake_check_whois)

    emails = [
        "alice@good.com",       # valid (smtp_confirmed)
        "alice@good.com",       # duplicate
        "bob@good.com",         # invalid (mailbox_not_found)
        "user@nomx.com",        # invalid (no_mx_record)
        "not-an-email",         # invalid (syntax_error)
        "spamtrap@good.com",    # do_not_use (spam_trap_keyword)
    ]

    job_id = "test-job"
    job_store.create(job_id, "inline-batch", len(emails))
    await runner.run_pipeline(emails, job_id)

    job = job_store.get(job_id)

    # ── Stage transitions: pipeline ran to completion ──────────────────────
    assert job["status"] == "complete"
    assert job["completedAt"] is not None
    p = job["progress"]
    assert p["stage1"]["total"] == 6
    assert p["stage1"]["passed"] == 3          # alice, bob, user@nomx reach DNS
    assert p["stage1"]["filtered"] == 3
    assert p["stage2"]["done"] == 3            # all three survivors get a DNS verdict
    assert p["stage3"]["total"] == 2           # only good.com has MX → SMTP
    assert p["stage3"]["done"] == 2

    # ── Final per-email statuses ───────────────────────────────────────────
    by_email: dict[str, list] = {}
    for r in job["results"]:
        by_email.setdefault(r.email, []).append(r)

    statuses = sorted((r.status, r.sub_status) for r in job["results"])
    assert ("valid", "smtp_confirmed") in statuses
    assert ("duplicate", "syntax_error") in statuses
    assert ("invalid", "mailbox_not_found") in statuses
    assert ("invalid", "no_mx_record") in statuses
    assert ("invalid", "syntax_error") in statuses
    assert ("do_not_use", "spam_trap_keyword") in statuses

    # valid result carries the quick Stage-4 score
    alice = next(r for r in job["results"] if r.email == "alice@good.com" and r.status == "valid")
    assert alice.score == 90

    # ── Counts ─────────────────────────────────────────────────────────────
    c = job["counts"]
    assert c["total"] == 6
    assert c["valid"] == 1
    assert c["invalid"] == 3
    assert c["reserved"] == 0
    assert c["do_not_use"] == 1
    assert c["duplicate"] == 1
    assert c["processed"] == 6
