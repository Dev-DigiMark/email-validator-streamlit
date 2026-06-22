"""Ported from backend/src/pipeline/scoring-core.ts.

Pure data-in/data-out scoring of a shard of reserved results. Mirrors the
runner Stage-4 reserved branch: builds ScoringInput, runs compute_score, then
applies promote/demote verdicts. Never mutates the job store.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from app.checks.scoring import (
    ScoringInput,
    compute_score,
    detect_format,
    matches_any,
)
from app.config import CONFIG
from app.models import ScoreBreakdownItem, ValidationResult
from app.store.patterns import PatternSnapshot


# Sub-statuses that must never be promoted to valid, regardless of score.
NEVER_PROMOTE = {
    "domain_not_found",  # DNS failure — domain unreachable, no MX record
    "accept_all",        # catch-all server accepts every address — proves nothing
}


@dataclass
class ScoringThresholds:
    promoteToValid: int
    demoteToInvalid: int


def _matches_confirmed_format(pattern: PatternSnapshot, domain: str, local_part: str) -> bool:
    formats = pattern.confirmedFormats.get(domain)
    if not formats:
        return False
    return detect_format(local_part) in formats


def _differs_from_domain_pattern(pattern: PatternSnapshot, domain: str, local_part: str) -> bool:
    formats = pattern.confirmedFormats.get(domain)
    resolved_valid = pattern.resolvedValid.get(domain, 0)
    if not formats or resolved_valid < 2:
        return False
    return detect_format(local_part) not in formats


def score_reserved_shard(
    reserved: list[ValidationResult],
    dns_cache: dict,
    website_cache: dict,
    pattern: PatternSnapshot,
    thresholds: ScoringThresholds,
    on_scored: Optional[Callable[[ValidationResult, int], None]] = None,
) -> list[ValidationResult]:
    out: list[ValidationResult] = []
    for i, source in enumerate(reserved):
        r = source.model_copy(deep=True)
        r.flags = list(source.flags)

        # no_mx_record: domain has no mail server — demote to invalid
        if r.sub_status == "no_mx_record":
            r.status = "invalid"
            r.score = 0
            r.confidence = "high"
            r.processing_stage = 4
            if on_scored:
                on_scored(r, i)
            out.append(r)
            continue

        at_idx = r.normalised.index("@")
        local_part = r.normalised[:at_idx]
        domain = r.normalised[at_idx + 1:]

        dns = dns_cache.get(domain)
        website = website_cache.get(domain)
        has_website = bool(getattr(website, "has_website", False)) if website is not None else False

        inp = ScoringInput(
            email=r.email,
            localPart=local_part,
            domain=domain,
            subStatus=r.sub_status,
            mxRecord=r.mx_record,
            smtpProvider=r.smtp_provider,
            hasSpf=getattr(dns, "spf_found", False) if dns is not None else False,
            hasDmarc=getattr(dns, "dmarc_found", False) if dns is not None else False,
            hasDkim=getattr(dns, "dkim_found", False) if dns is not None else False,
            mxOnBlacklist=("server_blacklisted" in r.flags)
            or (getattr(dns, "domain_blacklisted", False) if dns is not None else False),
            isCatchAll=r.sub_status == "accept_all",
            isRoleAddress=r.is_role_address,
            isFreeProvider=r.is_free_provider,
            hasWebsite=has_website,
            matchesConfirmedPattern=_matches_confirmed_format(pattern, domain, local_part),
            differsFromDomainPattern=_differs_from_domain_pattern(pattern, domain, local_part),
            domainResolveRate=pattern.resolveRates.get(domain, 0),
            domainBounceRate=pattern.bounceRates.get(domain, 0),
            domainAgeDays=getattr(dns, "domain_age_days", -1) if dns is not None else -1,
        )

        result = compute_score(inp)
        r.score = result.score
        r.score_breakdown = [ScoreBreakdownItem(**sig) for sig in result.appliedSignals]
        r.processing_stage = 4

        has_positive_proof = r.sub_status == "smtp_confirmed"
        is_defensive_provider = matches_any(
            r.smtp_provider, CONFIG["scoringEngine"]["defensiveProviders"]
        ) or matches_any(r.mx_record, CONFIG["scoringEngine"]["defensiveProviders"])
        reputation_promotion = (
            CONFIG["scoringEngine"]["allowReputationPromotion"] and not is_defensive_provider
        )
        can_promote = (r.sub_status not in NEVER_PROMOTE) and (
            has_positive_proof or reputation_promotion
        )

        if can_promote and result.score >= thresholds.promoteToValid:
            r.status = "valid"
            r.confidence = "medium"
            r.promoted_from_reserved = True
        elif result.score < thresholds.demoteToInvalid:
            r.status = "invalid"
            r.confidence = "medium"
            r.demoted_from_reserved = True

        if on_scored:
            on_scored(r, i)
        out.append(r)

    return out
