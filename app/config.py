"""Ported from backend/src/config/index.ts — values and strings match exactly.

Exposed as CONFIG, a frozen (read-only) mapping.
"""
from __future__ import annotations

import os
from types import MappingProxyType


def _env_bool(name: str) -> bool:
    return os.environ.get(name) == "true"


_CONFIG = {
    "server": {
        "port": int(os.environ.get("PORT") or 0) or 3001,
        "host": os.environ.get("HOST") or "localhost",
        "corsOrigin": os.environ.get("CORS_ORIGIN") or "http://localhost:3000",
    },
    "pipeline": {
        "dnsConcurrency": 20,
        "smtpDomainConcurrency": 10,
        "sseHeartbeatMs": 5000,
        "maxEmailsPerJob": 100000,
    },
    "workers": {
        "count": 4,
        "minBatchPerWorker": 10,
    },
    "smtp": {
        "connectTimeoutMs": 5000,
        "responseTimeoutMs": 8000,
        "greylistRetryDelayMs": 180000,
        "maxRetries": 3,
        "ports": [
            {"port": 25, "mode": "plain"},
            {"port": 2525, "mode": "starttls"},
            {"port": 587, "mode": "starttls"},
            {"port": 465, "mode": "implicit-tls"},
        ],
        "heloDomain": os.environ.get("HELO_DOMAIN") or "mail-checker.local",
        "fromAddress": os.environ.get("SMTP_FROM") or "verify@mail-checker.local",
        "domainConcurrencyLimits": {
            "strict": 1,
            "moderate": 2,
            "default": 5,
        },
        "strictDomains": [
            "gmail.com", "googlemail.com",
            "outlook.com", "hotmail.com", "live.com", "msn.com", "microsoft.com",
        ],
        "moderateDomains": [
            "yahoo.com", "yahoo.co.uk", "yahoo.fr", "yahoo.de",
            "icloud.com", "me.com", "mac.com",
            "protonmail.com", "proton.me", "fastmail.com",
        ],
    },
    "smtpParser": {
        "mailboxNotFound": [
            "no such user", "user unknown", "user does not exist",
            "invalid mailbox", "mailbox not found", "no mailbox",
            "does not exist", "unknown user", "invalid recipient",
            "recipient rejected", "recipient address rejected",
            "bad destination mailbox", "mailbox unavailable",
        ],
        "mailboxFull": [
            "over quota", "mailbox full", "quota exceeded", "insufficient storage",
        ],
        "mailboxDisabled": [
            "disabled", "account is inactive", "no longer active",
            "no longer here", "account closed",
        ],
        "mailboxSuspended": [
            "suspended", "account suspended",
        ],
        "ipReputation": [
            "blocked", "blacklisted", "listed", "reputation",
            "denied", "prohibited", "not permitted",
            "connection refused", "access denied", "ip block",
            "spamhaus", "barracuda", "spamcop",
        ],
        "policyRejection": [
            "policy violation", "not accepted", "relay not permitted",
            "relay denied", "not allowed", "unauthorized",
            "authentication required", "not authorised",
        ],
    },
    "dns": {
        "timeoutMs": 3000,
        "cacheTtlMs": 24 * 60 * 60 * 1000,
    },
    "resultCache": {
        "enabled": _env_bool("RESULT_CACHE_ENABLED"),
    },
    "roles": {
        "rejected": ["noreply", "no-reply", "no_reply", "donotreply", "do-not-reply"],
        "flagged": [
            "info", "admin", "support", "sales", "contact",
            "help", "billing", "team", "office", "hello",
            "webmaster", "postmaster", "hostmaster", "abuse",
        ],
    },
    "scoring": {
        "baseValid": 100,
        "deductions": {
            "reserved": 25,
            "roleAddress": 15,
            "freeProvider": 5,
            "infrastructureRisk": 10,
            "blacklistedServer": 40,
            "possibleTrap": 50,
        },
    },
    "export": {
        "tmpDir": os.environ.get("EXPORT_TMP_DIR") or "/tmp",
        "fileRetentionMs": 5 * 60 * 1000,
    },
    "scoringEngine": {
        "thresholds": {
            "promoteToValid": 85,
            "demoteToInvalid": 25,
        },
        "allowReputationPromotion": _env_bool("ALLOW_REPUTATION_PROMOTION"),
        "baseScore": 50,
        "signals": {
            "domainAgeOver5Years": 15,
            "domainAgeUnder6Months": -25,
            "hasSpfDkimDmarc": 10,
            "hasPartialAuth": 5,
            "mxReputableProvider": 10,
            "mxOnBlacklist": -30,
            "domainHasWebsite": 10,
            "domainNoWebsite": -5,
            "formatFirstnameLastname": 12,
            "formatInitialLastname": 10,
            "formatRealisticName": 8,
            "formatRandomAlphanumeric": -20,
            "formatContainsNumbers": -3,
            "formatTooLong": -8,
            "matchesConfirmedPattern": 20,
            "differsFromDomainPattern": -10,
            "domainHighResolveRate": 15,
            "domainHighBounceRate": -25,
            "defensiveProvider": 0,
            "honestProvider": -15,
            "catchAllBusinessProvider": 0,
            "catchAllSharedHosting": 0,
            "roleAddress": -10,
            "freeProvider": -5,
            "confirmedExternalSource": 20,
        },
        "defensiveProviders": [
            "protection.outlook.com",
            "mail.protection.outlook.com",
            "mimecast",
            "proofpoint",
            "barracuda",
            "sophos",
            "fortinet",
            "ironport",
            "cisco",
        ],
        "honestProviders": [
            "google.com",
            "googlemail.com",
            "gmail-smtp-in",
            "yahoodns.net",
            "yahoo.com",
            "aol.com",
        ],
        "reputableMxProviders": [
            "google.com", "googlemail.com", "aspmx.l.google.com",
            "outlook.com", "protection.outlook.com",
            "zoho.com", "zoho.eu",
            "fastmail.com", "messagingengine.com",
            "mimecast.com", "pphosted.com",
            "barracudanetworks.com",
            "emailsrvr.com",
            "proofpoint.com",
            "awsapps.com",
        ],
        "sharedHostingMx": [
            "hostinger", "cpanel", "plesk", "namecheap",
            "godaddy", "secureserver.net", "bluehost", "hostgator",
        ],
        "websiteCheck": {
            "enabled": True,
            "timeoutMs": 5000,
            "cacheTtlMs": 24 * 60 * 60 * 1000,
        },
    },
    "dnsbl": {
        "zones": [
            "zen.spamhaus.org",
            "b.barracudacentral.org",
            "bl.spamcop.net",
        ],
    },
}


def _freeze(value):
    """Deep read-only view: dicts -> MappingProxyType, lists -> tuples."""
    if isinstance(value, dict):
        return MappingProxyType({k: _freeze(v) for k, v in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(v) for v in value)
    return value


CONFIG = _freeze(_CONFIG)
