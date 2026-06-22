"""Ported from backend/src/pipeline/runner.ts + dns-smtp-shard.ts.

run_pipeline is the async 4-stage pipeline. Concurrency uses pure asyncio:
  - Stage 2 (DNS): asyncio.Semaphore(dnsConcurrency) instead of AsyncQueue.
  - Stage 3 (SMTP): a per-domain asyncio.Semaphore map honouring the same
    strict=1 / moderate=2 / default=5 limits as the TS DomainQueue.
  - Stage 4 scoring website fan-out: Semaphore(10) like the TS AsyncQueue(10),
    and the 180s greylist retry runs via asyncio.sleep in parallel with scoring.
No worker threads, no sockets — progress counters are written to the job store
for the polling endpoints. Status/sub_status strings and numeric thresholds
match the TS exactly.
"""
from __future__ import annotations

import asyncio
import re
from typing import Optional

from app.checks.dns import DomainDNSResult, check_domain
from app.checks.lists import (
    check_role,
    has_spam_trap_keyword,
    is_disposable,
    is_duplicate,
    is_free_provider,
)
from app.checks.smtp import check_catch_all, check_mailbox
from app.checks.syntax import check_syntax
from app.checks.website import check_website
from app.checks.whois import check_whois
from app.config import CONFIG
from app.models import ValidationResult
from app.pipeline.scoring_core import ScoringThresholds, score_reserved_shard
from app.store.jobs import job_store
from app.store.patterns import pattern_store

_NO_REPLY_RE = re.compile(r"no.?reply|donotreply", re.I)
_NON_NAME_RE = re.compile(r"[^a-zA-Z0-9 ]")
_SEP_RE = re.compile(r"[._-]+")


# ── Stage 1 metadata helpers ──────────────────────────────────────────────────


def _parse_full_name(local_part: str) -> str:
    spaced = _NON_NAME_RE.sub("", _SEP_RE.sub(" ", local_part)).strip()
    if not spaced:
        return "N/A"
    words = [w for w in spaced.split() if w]
    return " ".join(w[0].upper() + w[1:].lower() for w in words)


def _count_local_part(local: str) -> dict:
    return {
        "alphabetical_count": len(re.findall(r"[a-zA-Z]", local)),
        "numerical_count": len(re.findall(r"[0-9]", local)),
        "unicode_symbol_count": sum(1 for c in local if ord(c) > 127),
    }


# ── Stage 2/3 preliminary scoring (ported from dns-smtp-shard.ts) ─────────────


def _compute_prelim_score(
    status: str, flags: list, blacklisted: bool, infrastructure_risk: bool
) -> int:
    if status in ("invalid", "do_not_use", "duplicate"):
        return 0
    d = CONFIG["scoring"]["deductions"]
    score = CONFIG["scoring"]["baseValid"]
    if status == "reserved":
        score -= d["reserved"]
    if "role_address" in flags:
        score -= d["roleAddress"]
    if "free_provider" in flags:
        score -= d["freeProvider"]
    if infrastructure_risk:
        score -= d["infrastructureRisk"]
    if blacklisted:
        score -= d["blacklistedServer"]
    if "possible_trap" in flags:
        score -= d["possibleTrap"]
    return max(0, score)


def _compute_confidence(status: str, sub_status: str) -> str:
    if status in ("valid", "do_not_use", "duplicate", "invalid"):
        return "high"
    if sub_status in ("smtp_timeout", "smtp_connection_failed", "ambiguous_rejection"):
        return "low"
    return "medium"


# ── Per-domain SMTP concurrency (ported from DomainQueue) ─────────────────────


def _domain_limit(domain: str) -> int:
    limits = CONFIG["smtp"]["domainConcurrencyLimits"]
    if domain in CONFIG["smtp"]["strictDomains"]:
        return limits["strict"]
    if domain in CONFIG["smtp"]["moderateDomains"]:
        return limits["moderate"]
    return limits["default"]


async def _check_mailbox_with_failover(email: str, mx_hosts: list[str]):
    """Try each MX host in order; fall through only on TCP-level failure."""
    for mx_host in mx_hosts:
        try:
            result = await check_mailbox(email, mx_host)
            if result.sub_status != "smtp_connection_failed":
                return result, mx_host
        except Exception:
            pass
    return None


def _default_dns_result() -> DomainDNSResult:
    import time

    return DomainDNSResult(
        has_mx=False, has_a_fallback=False, spf_found=False, dmarc_found=False,
        dkim_found=False, blacklisted=False, domain_blacklisted=False,
        infrastructure_risk=False, domain_age_days=-1, cached_at=time.time() * 1000,
    )


async def _run_dns_smtp_shard(emails_by_domain, on_result, on_dns_result) -> None:
    """Stage 2 (DNS) + Stage 3 (SMTP) for a set of domains. Pure data-in /
    callbacks-out — mirrors runDnsSmtpShard line-for-line."""
    domain_map = dict(emails_by_domain)

    # ── Stage 2: DNS verification ──────────────────────────────────────────
    dns_sem = asyncio.Semaphore(CONFIG["pipeline"]["dnsConcurrency"])
    stage3_map: dict[str, dict] = {}

    async def dns_task(domain: str, results: list[ValidationResult]) -> None:
        async with dns_sem:
            try:
                dns_result = await check_domain(domain)
                on_dns_result(domain, dns_result)

                if not dns_result.has_mx and not dns_result.has_a_fallback:
                    for r in results:
                        on_result(r.model_copy(update={
                            "status": "invalid", "sub_status": "no_mx_record",
                            "score": 0, "confidence": "high",
                            "implicit_mx_record": False, "smtp_accessible": False,
                            "processing_stage": 2,
                        }))
                    return

                for r in results:
                    if dns_result.blacklisted:
                        r.flags.append("server_blacklisted")
                    if dns_result.infrastructure_risk:
                        r.flags.append("infrastructure_risk")

                if dns_result.mx_record:
                    stage3_map[domain] = {
                        "results": results,
                        "mx_hosts": dns_result.mx_records or [dns_result.mx_record],
                        "primary_mx": dns_result.mx_record,
                        "blacklisted": dns_result.blacklisted,
                        "infrastructure_risk": dns_result.infrastructure_risk,
                    }
                else:
                    # A fallback but no MX — implicit_mx_record
                    for r in results:
                        on_result(r.model_copy(update={
                            "status": "reserved", "sub_status": "no_mx_record",
                            "score": _compute_prelim_score(
                                "reserved", r.flags, dns_result.blacklisted,
                                dns_result.infrastructure_risk),
                            "confidence": "medium",
                            "implicit_mx_record": True, "smtp_accessible": False,
                            "processing_stage": 2,
                        }))
            except Exception:
                on_dns_result(domain, _default_dns_result())
                for r in results:
                    on_result(r.model_copy(update={
                        "status": "reserved", "sub_status": "domain_not_found",
                        "score": 0, "confidence": "medium",
                        "implicit_mx_record": False, "smtp_accessible": False,
                        "processing_stage": 2,
                    }))

    await asyncio.gather(*(dns_task(d, rs) for d, rs in domain_map.items()))

    # ── Stage 3: SMTP verification ─────────────────────────────────────────
    domain_sems: dict[str, asyncio.Semaphore] = {}
    retry_queue: list[dict] = []

    def get_sem(domain: str) -> asyncio.Semaphore:
        sem = domain_sems.get(domain)
        if sem is None:
            sem = asyncio.Semaphore(_domain_limit(domain))
            domain_sems[domain] = sem
        return sem

    async def smtp_domain_task(domain: str, info: dict) -> None:
        results = info["results"]
        mx_hosts = info["mx_hosts"]
        primary_mx = info["primary_mx"]
        blacklisted = info["blacklisted"]
        infrastructure_risk = info["infrastructure_risk"]

        try:
            is_catch_all = await check_catch_all(domain, primary_mx)
        except Exception:
            is_catch_all = False

        if is_catch_all:
            for r in results:
                flags = [*r.flags, "catch_all"]
                on_result(r.model_copy(update={
                    "status": "reserved", "sub_status": "accept_all",
                    "score": _compute_prelim_score(
                        "reserved", flags, blacklisted, infrastructure_risk),
                    "confidence": "medium", "flags": flags,
                    "mx_record": primary_mx, "smtp_accessible": True,
                    "processing_stage": 3,
                }))
            return

        sem = get_sem(domain)

        async def email_task(r: ValidationResult) -> None:
            async with sem:
                try:
                    hit = await _check_mailbox_with_failover(r.email, mx_hosts)
                    if not hit:
                        on_result(r.model_copy(update={
                            "status": "reserved", "sub_status": "smtp_connection_failed",
                            "score": 0, "confidence": "low", "mx_record": primary_mx,
                            "smtp_accessible": False, "processing_stage": 3,
                        }))
                        return

                    smtp_result, mx_host = hit

                    if smtp_result.should_retry:
                        retry_queue.append({
                            "result": r, "mx_hosts": mx_hosts, "primary_mx": mx_host,
                            "blacklisted": blacklisted,
                            "infrastructure_risk": infrastructure_risk,
                        })
                        return

                    if smtp_result.exists is True:
                        status, sub_status = "valid", "smtp_confirmed"
                    elif smtp_result.exists is False:
                        status, sub_status = "invalid", smtp_result.sub_status
                    else:
                        status, sub_status = "reserved", smtp_result.sub_status

                    flags = list(r.flags)
                    on_result(r.model_copy(update={
                        "status": status, "sub_status": sub_status,
                        "score": _compute_prelim_score(
                            status, flags, blacklisted, infrastructure_risk),
                        "confidence": _compute_confidence(status, sub_status),
                        "flags": flags, "mx_record": mx_host,
                        "smtp_provider": smtp_result.smtp_provider,
                        "smtp_response": smtp_result.smtp_response,
                        "smtp_response_code": smtp_result.smtp_response_code,
                        "smtp_accessible": smtp_result.smtp_accessible,
                        "processing_stage": 3,
                    }))
                except Exception:
                    on_result(r.model_copy(update={
                        "status": "reserved", "sub_status": "smtp_connection_failed",
                        "score": 0, "confidence": "low", "mx_record": primary_mx,
                        "processing_stage": 3,
                    }))

        await asyncio.gather(*(email_task(r) for r in results))

    await asyncio.gather(*(smtp_domain_task(d, info) for d, info in stage3_map.items()))

    # Emit shouldRetry emails as greylisted — the runner-level Stage 4 retry
    # handles the actual re-check in parallel with scoring.
    for item in retry_queue:
        r = item["result"]
        on_result(r.model_copy(update={
            "status": "reserved", "sub_status": "greylisted",
            "score": _compute_prelim_score(
                "reserved", r.flags, item["blacklisted"], item["infrastructure_risk"]),
            "confidence": _compute_confidence("reserved", "greylisted"),
            "mx_record": item["primary_mx"], "smtp_accessible": True,
            "processing_stage": 3,
        }))


def _assign(target: ValidationResult, source: ValidationResult) -> None:
    """Mirror TS Object.assign(refs[i], res): copy scored fields onto the
    in-place job result so the polling/results endpoints see the verdict."""
    for field, value in source.model_dump().items():
        setattr(target, field, value)


async def run_pipeline(emails: list[str], job_id: str) -> None:
    job = job_store.get(job_id)
    if not job:
        return

    job_store.update(job_id, status="stage1")

    # ── Layer 0: result cache disabled by default — process every email ─────
    emails_to_process = list(emails)

    # ── Stage 1: syntax, duplicates, lists ─────────────────────────────────
    seen: set[str] = set()
    stage2_queue: list[ValidationResult] = []

    for raw_email in emails_to_process:
        try:
            syntax_result = check_syntax(raw_email)

            if not syntax_result.passed:
                raw_at = raw_email.find("@")
                fallback_local = (raw_email[:raw_at] if raw_at > 0 else raw_email).lower()
                job_store.add_result(job_id, ValidationResult(
                    email=raw_email, normalised=raw_email.lower().strip(),
                    status="invalid", sub_status=syntax_result.sub_status or "syntax_error",
                    score=0, confidence="high", flags=syntax_result.flags,
                    did_you_mean=syntax_result.did_you_mean,
                    is_free_provider=False, is_role_address=False, is_disposable=False,
                    processing_stage=1, full_name=_parse_full_name(fallback_local),
                    **_count_local_part(fallback_local),
                    is_no_reply=bool(_NO_REPLY_RE.search(fallback_local)),
                    implicit_mx_record=False, smtp_accessible=False,
                ))
                job_store.increment_count(job_id, "invalid")
                continue

            normalised = syntax_result.normalised
            flags = list(syntax_result.flags)

            if is_duplicate(normalised, seen):
                dup_at = normalised.index("@")
                dup_local = normalised[:dup_at]
                job_store.add_result(job_id, ValidationResult(
                    email=raw_email, normalised=normalised,
                    status="duplicate", sub_status="syntax_error",
                    score=0, confidence="high", flags=flags,
                    did_you_mean=syntax_result.did_you_mean,
                    is_free_provider=False, is_role_address=False, is_disposable=False,
                    processing_stage=1, full_name=_parse_full_name(dup_local),
                    **_count_local_part(dup_local),
                    is_no_reply=bool(_NO_REPLY_RE.search(dup_local)),
                    implicit_mx_record=False, smtp_accessible=False,
                ))
                job_store.increment_count(job_id, "duplicate")
                continue

            at_index = normalised.index("@")
            local = normalised[:at_index]
            domain = normalised[at_index + 1:]

            meta_fields = {
                "full_name": _parse_full_name(local),
                **_count_local_part(local),
                "is_no_reply": bool(_NO_REPLY_RE.search(local)),
                "implicit_mx_record": False,
                "smtp_accessible": False,
            }

            disposable = is_disposable(domain)
            free_provider = is_free_provider(domain)
            role_check = check_role(local)
            spam_trap = has_spam_trap_keyword(local)

            if disposable:
                flags.append("disposable")
            if free_provider:
                flags.append("free_provider")
            if role_check["flagged"]:
                flags.append("role_address")
            if spam_trap:
                flags.append("possible_trap")

            if spam_trap:
                job_store.add_result(job_id, ValidationResult(
                    email=raw_email, normalised=normalised,
                    status="do_not_use", sub_status="spam_trap_keyword",
                    score=0, confidence="high", flags=flags,
                    did_you_mean=syntax_result.did_you_mean,
                    is_free_provider=free_provider, is_role_address=role_check["flagged"],
                    is_disposable=disposable, processing_stage=1, **meta_fields,
                ))
                job_store.increment_count(job_id, "do_not_use")
                continue

            if disposable:
                job_store.add_result(job_id, ValidationResult(
                    email=raw_email, normalised=normalised,
                    status="invalid", sub_status="disposable",
                    score=0, confidence="high", flags=flags,
                    did_you_mean=syntax_result.did_you_mean,
                    is_free_provider=free_provider, is_role_address=role_check["flagged"],
                    is_disposable=True, processing_stage=1, **meta_fields,
                ))
                job_store.increment_count(job_id, "invalid")
                continue

            if role_check["rejected"]:
                job_store.add_result(job_id, ValidationResult(
                    email=raw_email, normalised=normalised,
                    status="do_not_use", sub_status="role_rejected",
                    score=0, confidence="high", flags=flags,
                    did_you_mean=syntax_result.did_you_mean,
                    is_free_provider=free_provider, is_role_address=True,
                    is_disposable=False, processing_stage=1, **meta_fields,
                ))
                job_store.increment_count(job_id, "do_not_use")
                continue

            stage2_queue.append(ValidationResult(
                email=raw_email, normalised=normalised,
                status="reserved", sub_status="temp_error",
                score=0, confidence="low", flags=flags,
                did_you_mean=syntax_result.did_you_mean,
                is_free_provider=free_provider, is_role_address=role_check["flagged"],
                is_disposable=False, processing_stage=1, **meta_fields,
            ))
        except Exception:
            job_store.add_result(job_id, ValidationResult(
                email=raw_email, normalised=raw_email.lower().strip(),
                status="reserved", sub_status="temp_error",
                score=0, confidence="low", flags=[],
                is_free_provider=False, is_role_address=False, is_disposable=False,
                processing_stage=1, full_name="N/A",
                alphabetical_count=0, numerical_count=0, unicode_symbol_count=0,
                is_no_reply=False, implicit_mx_record=False, smtp_accessible=False,
            ))
            job_store.increment_count(job_id, "reserved")

    job_store.update(job_id, status="stage2")

    # ── Stages 2+3: DNS + SMTP, grouped by domain ──────────────────────────
    domain_map: dict[str, list[ValidationResult]] = {}
    for result in stage2_queue:
        domain = result.normalised[result.normalised.index("@") + 1:]
        domain_map.setdefault(domain, []).append(result)

    dns_result_cache: dict[str, DomainDNSResult] = {}

    # ── Per-stage progress tracking ────────────────────────────────────────
    stage1_total = len(emails)
    stage2_total = len(stage2_queue)
    counters = {"stage2_done": 0, "stage3_total": 0, "stage3_done": 0,
                "stage4_total": 0, "stage4_done": 0}

    def build_progress() -> dict:
        return {
            "stage1": {"done": stage1_total, "total": stage1_total,
                       "filtered": stage1_total - stage2_total, "passed": stage2_total},
            "stage2": {"done": counters["stage2_done"], "total": stage2_total},
            "stage3": {"done": counters["stage3_done"], "total": counters["stage3_total"]},
            "stage4": {"done": counters["stage4_done"], "total": counters["stage4_total"]},
        }

    def emit_progress() -> None:
        job_store.update(job_id, progress=build_progress())

    def handle_stage3_result(result: ValidationResult) -> None:
        job_store.add_result(job_id, result)
        job_store.increment_count(job_id, result.status)
        if result.processing_stage == 3:
            counters["stage3_done"] += 1

    def handle_dns(domain: str, dns_result: DomainDNSResult) -> None:
        dns_result_cache[domain] = dns_result
        email_count = len(domain_map.get(domain, []))
        counters["stage2_done"] += email_count
        if dns_result.mx_record:
            counters["stage3_total"] += email_count

    await _run_dns_smtp_shard(domain_map, handle_stage3_result, handle_dns)
    emit_progress()

    job_store.update(job_id, status="stage3")
    emit_progress()

    # ── Stage 4: confidence scoring ────────────────────────────────────────
    job_store.update(job_id, status="stage4")
    results = job_store.get(job_id)["results"]

    # 1. Populate the pattern store from SMTP-confirmed emails.
    for r in results:
        if r.status == "valid" and r.sub_status == "smtp_confirmed":
            at_idx = r.normalised.index("@")
            pattern_store.record_valid(r.normalised[at_idx + 1:], r.normalised[:at_idx])

    # 2. Split reserved into greylisted (pending retry) and everything else.
    all_reserved = [r for r in results if r.status == "reserved"]
    greylisted = [r for r in all_reserved if r.sub_status == "greylisted"]
    other_reserved = [r for r in all_reserved if r.sub_status != "greylisted"]

    # 3. Quick score for final (non-reserved) results.
    for r in results:
        if r.status != "reserved":
            r.score = 90 if r.status == "valid" else 0

    thresholds = ScoringThresholds(
        promoteToValid=CONFIG["scoringEngine"]["thresholds"]["promoteToValid"],
        demoteToInvalid=CONFIG["scoringEngine"]["thresholds"]["demoteToInvalid"],
    )

    def apply_score_count(res: ValidationResult) -> None:
        if res.promoted_from_reserved:
            job_store.increment_count(job_id, "promoted_to_valid")
            job_store.increment_count(job_id, "reserved", -1)
            job_store.increment_count(job_id, "valid", 1)
        elif res.demoted_from_reserved:
            job_store.increment_count(job_id, "demoted_to_invalid")
            job_store.increment_count(job_id, "reserved", -1)
            job_store.increment_count(job_id, "invalid", 1)
        elif res.status == "invalid":
            job_store.increment_count(job_id, "reserved", -1)
            job_store.increment_count(job_id, "invalid", 1)

    async def score_reserved_batch(reserved_refs: list[ValidationResult]) -> None:
        if not reserved_refs:
            return

        reserved_by_domain: dict[str, list[ValidationResult]] = {}
        reserved_domains: list[str] = []
        for r in reserved_refs:
            d = r.normalised[r.normalised.index("@") + 1:]
            if d not in reserved_by_domain:
                reserved_by_domain[d] = []
                reserved_domains.append(d)
            reserved_by_domain[d].append(r)
            pattern_store.record_reserved(d)

        pattern_data = pattern_store.snapshot_for(reserved_domains)
        website_sem = asyncio.Semaphore(10)

        async def domain_task(domain: str) -> None:
            async with website_sem:
                website_result, whois_result = await asyncio.gather(
                    check_website(domain),
                    _safe_whois(domain),
                )
                refs = reserved_by_domain.get(domain, [])
                website_cache = {domain: website_result}

                def on_scored(res: ValidationResult, i: int) -> None:
                    _assign(refs[i], res)
                    refs[i].whois_registrar = whois_result.registrar
                    refs[i].whois_country = whois_result.country
                    refs[i].whois_server = whois_result.whois_server
                    apply_score_count(res)

                score_reserved_shard(
                    refs, dns_result_cache, website_cache, pattern_data,
                    thresholds, on_scored,
                )
                counters["stage4_done"] += len(refs)
                emit_progress()

        await asyncio.gather(*(domain_task(d) for d in reserved_domains))

    counters["stage4_total"] = len(all_reserved)
    counters["stage4_done"] = 0
    emit_progress()

    async def greylist_retry() -> None:
        if not greylisted:
            return
        await asyncio.sleep(CONFIG["smtp"]["greylistRetryDelayMs"] / 1000)

        still_reserved: list[ValidationResult] = []

        async def retry_one(r: ValidationResult) -> None:
            mx_host = r.mx_record
            if not mx_host:
                still_reserved.append(r)
                return
            try:
                smtp_result = await check_mailbox(r.email, mx_host)
                if smtp_result.exists is True:
                    r.status = "valid"
                    r.sub_status = "smtp_confirmed"
                    r.promoted_from_reserved = True
                    r.score = 90
                    r.confidence = "medium"
                    job_store.increment_count(job_id, "promoted_to_valid")
                    job_store.increment_count(job_id, "reserved", -1)
                    job_store.increment_count(job_id, "valid", 1)
                elif smtp_result.exists is False:
                    r.status = "invalid"
                    r.sub_status = smtp_result.sub_status
                    r.score = 0
                    r.confidence = "high"
                    job_store.increment_count(job_id, "reserved", -1)
                    job_store.increment_count(job_id, "invalid", 1)
                else:
                    still_reserved.append(r)
            except Exception:
                still_reserved.append(r)
            counters["stage4_done"] += 1
            emit_progress()

        await asyncio.gather(*(retry_one(r) for r in greylisted))

        if still_reserved:
            await score_reserved_batch(still_reserved)
            emit_progress()

    await asyncio.gather(
        score_reserved_batch(other_reserved),
        greylist_retry(),
    )
    emit_progress()

    counters["stage4_done"] = counters["stage4_total"]
    from datetime import datetime

    job_store.update(job_id, status="complete", completedAt=datetime.now(),
                     progress=build_progress())


async def _safe_whois(domain: str):
    try:
        return await check_whois(domain)
    except Exception:
        from app.checks.whois import WhoisResult

        return WhoisResult(registrar=None, country=None, whois_server=None, creation_date=None)
