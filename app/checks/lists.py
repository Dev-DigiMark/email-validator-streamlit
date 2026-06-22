"""Ported from backend/src/checks/lists.ts.

Loads the SAME data files (app/data/) and reproduces the TS list-check
behaviour exactly: disposable / free-provider / role / spam-trap / duplicate.
"""
from __future__ import annotations

import os

from app.config import CONFIG

_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")


def _load_set(filename: str, fallback: list[str] | None = None) -> set[str]:
    try:
        with open(os.path.join(_DATA_DIR, filename), encoding="utf8") as f:
            content = f.read()
        return {
            line
            for raw in content.split("\n")
            for line in (raw.strip().lower(),)
            if len(line) > 0 and not line.startswith("#")
        }
    except OSError:
        return set(fallback or [])


# Full reject-list (~243k domains). Kept as a set so is_disposable() stays O(1).
# The 3-domain fallback covers a missing file so the app never crashes.
_disposable_domains = _load_set(
    "disposed_email.conf", ["mailinator.com", "tempmail.com", "fakeinbox.com"]
)

_free_provider_domains = _load_set("free_providers.txt")
_role_prefixes = _load_set("role_prefixes.txt")

_rejected_roles = set(CONFIG["roles"]["rejected"])
_flagged_roles = set(CONFIG["roles"]["flagged"])

_SPAM_TRAP_KEYWORDS = ["spam", "trap", "honeypot", "spamtrap"]


def is_duplicate(normalised: str, seen: set[str]) -> bool:
    """Check if normalised email is a duplicate within the current job's seen set."""
    if normalised in seen:
        return True
    seen.add(normalised)
    return False


def is_disposable(domain: str) -> bool:
    """Check if domain is a known disposable email provider."""
    return domain.lower() in _disposable_domains


def check_role(local_part: str) -> dict[str, bool]:
    """Check role status of local part."""
    lower = local_part.lower()
    if lower in _rejected_roles or lower in _role_prefixes:
        # rejected takes priority: check CONFIG rejected list first
        if lower in _rejected_roles:
            return {"rejected": True, "flagged": False}
        # role_prefixes that aren't in rejected are flagged
        return {"rejected": False, "flagged": True}
    if lower in _flagged_roles:
        return {"rejected": False, "flagged": True}
    return {"rejected": False, "flagged": False}


def is_free_provider(domain: str) -> bool:
    """Check if domain is a known free email provider."""
    return domain.lower() in _free_provider_domains


def has_spam_trap_keyword(local_part: str) -> bool:
    """Check if local part contains a spam trap keyword."""
    lower = local_part.lower()
    return any(kw in lower for kw in _SPAM_TRAP_KEYWORDS)
