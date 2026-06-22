"""Ported from backend/src/checks/scoring.ts.

Stage-4 scoring engine. detectFormat / looksLikeRealName / isRandomAlphanumeric
/ matchesAny / computeScore ported line-for-line; signal names, point values and
thresholds come from CONFIG and match the TS exactly.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from app.config import CONFIG

# EmailFormat literal values (mirror app/store/patterns.py)
EmailFormat = str

_ALPHA = re.compile(r"^[a-z]+$")
_DIGIT = re.compile(r"\d")
_SEP = re.compile(r"[._-]")
_VOWEL = re.compile(r"[aeiou]")


@dataclass
class ScoringInput:
    email: str
    localPart: str
    domain: str
    subStatus: str
    hasSpf: bool
    hasDmarc: bool
    hasDkim: bool
    mxOnBlacklist: bool
    isCatchAll: bool
    isRoleAddress: bool
    isFreeProvider: bool
    hasWebsite: bool
    matchesConfirmedPattern: bool
    differsFromDomainPattern: bool
    domainResolveRate: float
    domainBounceRate: float
    domainAgeDays: float
    mxRecord: Optional[str] = None
    smtpProvider: Optional[str] = None


@dataclass
class ScoringResult:
    score: int
    appliedSignals: list[dict]


def detect_format(local_part: str) -> EmailFormat:
    if "_" in local_part:
        return "firstname_lastname"
    dot_parts = local_part.split(".")
    if (
        len(dot_parts) == 2
        and _ALPHA.match(dot_parts[0])
        and _ALPHA.match(dot_parts[1])
    ):
        return "firstname.lastname"
    if not _ALPHA.match(local_part):
        return "other"
    if len(local_part) <= 4:
        return "firstname"
    if len(local_part) <= 7:
        return "initiallastname"
    return "firstnamelastname"


def looks_like_real_name(local_part: str) -> bool:
    stripped = _SEP.sub("", local_part)
    if not _ALPHA.match(stripped):
        return False
    if len(local_part) < 3 or len(local_part) > 30:
        return False
    separators = len(_SEP.findall(local_part))
    return separators <= 1


def is_random_alphanumeric(local_part: str) -> bool:
    if not _DIGIT.search(local_part):
        return False
    if "." in local_part or "_" in local_part or "-" in local_part:
        return False
    vowels = len(_VOWEL.findall(local_part))
    return vowels / len(local_part) < 0.2


def matches_any(value: Optional[str], items) -> bool:
    if not value:
        return False
    lower = value.lower()
    return any(p.lower() in lower for p in items)


def compute_score(inp: ScoringInput) -> ScoringResult:
    s = CONFIG["scoringEngine"]["signals"]
    applied: list[dict] = []
    score = CONFIG["scoringEngine"]["baseScore"]

    def apply(signal: str, points: int) -> None:
        nonlocal score
        if points == 0:
            return
        applied.append({"signal": signal, "points": points})
        score += points

    # ── Domain reputation ────────────────────────────────────────────────────
    if inp.domainAgeDays >= 0:
        if inp.domainAgeDays > 1825:
            apply("domainAgeOver5Years", s["domainAgeOver5Years"])
        elif inp.domainAgeDays < 180:
            apply("domainAgeUnder6Months", s["domainAgeUnder6Months"])

    if inp.hasSpf and inp.hasDkim and inp.hasDmarc:
        apply("hasSpfDkimDmarc", s["hasSpfDkimDmarc"])
    elif (inp.hasSpf or inp.hasDmarc) and not (inp.hasSpf and inp.hasDkim and inp.hasDmarc):
        apply("hasPartialAuth", s["hasPartialAuth"])

    if matches_any(inp.mxRecord, CONFIG["scoringEngine"]["reputableMxProviders"]):
        apply("mxReputableProvider", s["mxReputableProvider"])

    if inp.mxOnBlacklist:
        apply("mxOnBlacklist", s["mxOnBlacklist"])

    if inp.hasWebsite:
        apply("domainHasWebsite", s["domainHasWebsite"])
    else:
        apply("domainNoWebsite", s["domainNoWebsite"])

    # ── Email pattern ────────────────────────────────────────────────────────
    fmt = detect_format(inp.localPart)
    if fmt == "firstname.lastname":
        apply("formatFirstnameLastname", s["formatFirstnameLastname"])
    elif fmt == "initiallastname":
        apply("formatInitialLastname", s["formatInitialLastname"])

    if looks_like_real_name(inp.localPart):
        apply("formatRealisticName", s["formatRealisticName"])
    if is_random_alphanumeric(inp.localPart):
        apply("formatRandomAlphanumeric", s["formatRandomAlphanumeric"])
    if _DIGIT.search(inp.localPart):
        apply("formatContainsNumbers", s["formatContainsNumbers"])
    if len(inp.localPart) > 20:
        apply("formatTooLong", s["formatTooLong"])

    # ── Historical patterns ──────────────────────────────────────────────────
    if inp.matchesConfirmedPattern:
        apply("matchesConfirmedPattern", s["matchesConfirmedPattern"])
    if inp.differsFromDomainPattern:
        apply("differsFromDomainPattern", s["differsFromDomainPattern"])
    if inp.domainResolveRate > 0.8:
        apply("domainHighResolveRate", s["domainHighResolveRate"])
    if inp.domainBounceRate > 0.5:
        apply("domainHighBounceRate", s["domainHighBounceRate"])

    # ── Provider behaviour ───────────────────────────────────────────────────
    is_defensive = matches_any(inp.smtpProvider, CONFIG["scoringEngine"]["defensiveProviders"]) or \
        matches_any(inp.mxRecord, CONFIG["scoringEngine"]["defensiveProviders"])
    is_honest = matches_any(inp.smtpProvider, CONFIG["scoringEngine"]["honestProviders"]) or \
        matches_any(inp.mxRecord, CONFIG["scoringEngine"]["honestProviders"])

    if is_defensive:
        apply("defensiveProvider", s["defensiveProvider"])
    elif is_honest and inp.subStatus != "smtp_confirmed":
        apply("honestProvider", s["honestProvider"])

    if inp.isCatchAll:
        is_reputable_mx = matches_any(inp.mxRecord, CONFIG["scoringEngine"]["reputableMxProviders"])
        is_shared_hosting = matches_any(inp.mxRecord, CONFIG["scoringEngine"]["sharedHostingMx"])
        if is_reputable_mx:
            apply("catchAllBusinessProvider", s["catchAllBusinessProvider"])
        elif is_shared_hosting:
            apply("catchAllSharedHosting", s["catchAllSharedHosting"])

    # ── Content ──────────────────────────────────────────────────────────────
    if inp.isRoleAddress:
        apply("roleAddress", s["roleAddress"])
    if inp.isFreeProvider:
        apply("freeProvider", s["freeProvider"])

    return ScoringResult(score=max(0, min(100, score)), appliedSignals=applied)
