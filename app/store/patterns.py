"""Ported from backend/src/store/patterns.ts.

In-memory PatternStore that learns confirmed local-part formats per domain
across a batch, plus the JSON-safe PatternSnapshot used by Stage-4 scoring.
detectFormat matches checks/scoring.detect_format exactly.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

EmailFormat = str

_ALPHA = re.compile(r"^[a-z]+$")


def _now_ms() -> float:
    return time.time() * 1000


@dataclass
class _DomainPattern:
    domain: str
    confirmedFormats: set[EmailFormat] = field(default_factory=set)
    totalReserved: int = 0
    resolvedValid: int = 0
    hardBounces: int = 0
    lastUpdated: float = field(default_factory=_now_ms)


@dataclass
class PatternSnapshot:
    """JSON-serialisable view of the pattern data needed by Stage 4 scoring."""
    confirmedFormats: dict[str, list[EmailFormat]]
    resolvedValid: dict[str, int]
    resolveRates: dict[str, float]
    bounceRates: dict[str, float]


class PatternStore:
    def __init__(self) -> None:
        self._patterns: dict[str, _DomainPattern] = {}

    def _get_or_create(self, domain: str) -> _DomainPattern:
        p = self._patterns.get(domain)
        if p is None:
            p = _DomainPattern(domain=domain)
            self._patterns[domain] = p
        return p

    def detect_format(self, local_part: str) -> EmailFormat:
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

    def record_valid(self, domain: str, local_part: str) -> None:
        p = self._get_or_create(domain)
        p.confirmedFormats.add(self.detect_format(local_part))
        p.resolvedValid += 1
        p.lastUpdated = _now_ms()

    def record_reserved(self, domain: str) -> None:
        p = self._get_or_create(domain)
        p.totalReserved += 1
        p.lastUpdated = _now_ms()

    def record_bounce(self, domain: str) -> None:
        p = self._get_or_create(domain)
        p.hardBounces += 1
        p.lastUpdated = _now_ms()

    def matches_confirmed_format(self, domain: str, local_part: str) -> bool:
        p = self._patterns.get(domain)
        if p is None or len(p.confirmedFormats) == 0:
            return False
        return self.detect_format(local_part) in p.confirmedFormats

    def differs_from_domain_pattern(self, domain: str, local_part: str) -> bool:
        p = self._patterns.get(domain)
        if p is None or len(p.confirmedFormats) == 0 or p.resolvedValid < 2:
            return False
        return self.detect_format(local_part) not in p.confirmedFormats

    def get_resolve_rate(self, domain: str) -> float:
        p = self._patterns.get(domain)
        if p is None or p.totalReserved == 0:
            return 0
        return p.resolvedValid / p.totalReserved

    def get_bounce_rate(self, domain: str) -> float:
        p = self._patterns.get(domain)
        if p is None or p.resolvedValid == 0:
            return 0
        return p.hardBounces / p.resolvedValid

    def snapshot_for(self, domains: list[str]) -> PatternSnapshot:
        confirmed_formats: dict[str, list[EmailFormat]] = {}
        resolved_valid: dict[str, int] = {}
        resolve_rates: dict[str, float] = {}
        bounce_rates: dict[str, float] = {}

        for domain in domains:
            p = self._patterns.get(domain)
            if p is None:
                continue
            confirmed_formats[domain] = list(p.confirmedFormats)
            resolved_valid[domain] = p.resolvedValid
            resolve_rates[domain] = self.get_resolve_rate(domain)
            bounce_rates[domain] = self.get_bounce_rate(domain)

        return PatternSnapshot(
            confirmedFormats=confirmed_formats,
            resolvedValid=resolved_valid,
            resolveRates=resolve_rates,
            bounceRates=bounce_rates,
        )


pattern_store = PatternStore()
