"""Ported from backend/src/checks/syntax.ts — behaviour matches exactly.

Loads the SAME TLD data file (app/data/tlds.txt) and reproduces normalisation,
Levenshtein typo correction (did_you_mean) and every sub_status string by hand.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Optional

_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")


def _load_tlds() -> set[str]:
    with open(os.path.join(_DATA_DIR, "tlds.txt"), encoding="utf8") as f:
        content = f.read()
    return {
        line
        for raw in content.split("\n")
        for line in (raw.strip().lower(),)
        if len(line) > 0 and not line.startswith("#")
    }


_tld_set = _load_tlds()

# Top-200 provider domains for typo detection
TOP_PROVIDERS = [
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "yahoo.fr",
    "yahoo.de", "yahoo.es", "yahoo.it", "hotmail.com", "hotmail.co.uk",
    "hotmail.fr", "hotmail.de", "outlook.com", "live.com", "msn.com",
    "icloud.com", "me.com", "mac.com", "protonmail.com", "proton.me",
    "fastmail.com", "fastmail.fm", "zoho.com", "aol.com", "aim.com",
    "mail.com", "email.com", "gmx.com", "gmx.de", "gmx.net",
    "web.de", "freenet.de", "t-online.de", "posteo.de", "mailbox.org",
    "tutanota.com", "tutamail.com", "tuta.io", "hey.com", "pm.me",
    "yandex.com", "yandex.ru", "mail.ru", "inbox.ru", "list.ru",
    "bk.ru", "rambler.ru", "qq.com", "163.com", "126.com",
    "sina.com", "sohu.com", "aliyun.com", "foxmail.com", "rediffmail.com",
    "indiatimes.com", "sify.com", "vsnl.com", "dataone.in", "naver.com",
    "daum.net", "hanmail.net", "kakao.com", "nate.com", "yahoo.co.jp",
    "docomo.ne.jp", "softbank.jp", "ezweb.ne.jp", "willcom.com", "i.softbank.jp",
    "orange.fr", "laposte.net", "sfr.fr", "free.fr", "wanadoo.fr",
    "libero.it", "virgilio.it", "alice.it", "tiscali.it", "tim.it",
    "telenet.be", "skynet.be", "proximus.be", "swing.be", "pandora.be",
    "terra.com.br", "bol.com.br", "uol.com.br", "globo.com", "ig.com.br",
    "btinternet.com", "virginmedia.com", "sky.com", "ntlworld.com", "talktalk.net",
    "blueyonder.co.uk", "btopenworld.com", "tiscali.co.uk", "lineone.net", "fsmail.net",
    "o2.pl", "wp.pl", "onet.pl", "interia.pl", "gazeta.pl",
    "seznam.cz", "centrum.cz", "email.cz", "atlas.cz", "volny.cz",
    "freemail.hu", "citromail.hu", "indamail.hu", "mailbox.hu", "vipmail.hu",
    "abv.bg", "mail.bg", "dir.bg", "netbg.com", "yahoo.bg",
    "inbox.lv", "one.lv", "apollo.lv", "balticom.lv", "tvnet.lv",
    "hot.ee", "mail.ee", "online.ee", "inbox.ee", "neti.ee",
    "ukr.net", "meta.ua", "i.ua", "email.ua", "bigmir.net",
    "tut.by", "mail.tut.by", "yandex.by", "rambler.by", "inbox.by",
    "yahoo.com.ar", "fibertel.com.ar", "speedy.com.ar", "arnet.com.ar", "hotmail.com.ar",
    "yahoo.com.mx", "hotmail.com.mx", "prodigy.net.mx", "telmex.net", "axtel.net",
    "yahoo.com.au", "optusnet.com.au", "bigpond.com", "bigpond.net.au", "iinet.net.au",
    "xtra.co.nz", "clear.net.nz", "paradise.net.nz", "ihug.co.nz", "slingshot.co.nz",
]

_LOCAL_RE = re.compile(r"^[a-z0-9._%+\-]+$")
_DOMAIN_RE = re.compile(r"^[a-z0-9.\-]+$")


@dataclass
class SyntaxCheckResult:
    passed: bool
    flags: list[str] = field(default_factory=list)
    sub_status: Optional[str] = None
    did_you_mean: Optional[str] = None
    normalised: Optional[str] = None


def _levenshtein(a: str, b: str) -> int:
    """Compute Levenshtein distance between two strings."""
    m = len(a)
    n = len(b)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if a[i - 1] == b[j - 1]:
                dp[i][j] = dp[i - 1][j - 1]
            else:
                dp[i][j] = 1 + min(dp[i - 1][j - 1], dp[i - 1][j], dp[i][j - 1])
    return dp[m][n]


def _find_typo_suggestion(domain: str) -> Optional[str]:
    """Find closest provider domain within Levenshtein distance 2."""
    best: Optional[str] = None
    best_dist = 3
    for provider in TOP_PROVIDERS:
        if provider == domain:
            return None
        dist = _levenshtein(domain, provider)
        if dist < best_dist:
            best_dist = dist
            best = provider
    return best if best_dist <= 2 else None


def _normalise_gmail(local: str, domain: str) -> tuple[str, bool]:
    """Normalise Gmail/Googlemail: strip dots and +suffix from local part."""
    if domain != "gmail.com" and domain != "googlemail.com":
        return local, False
    plus_index = local.find("+")
    base = local[:plus_index] if plus_index >= 0 else local
    stripped = base.replace(".", "")
    alias_detected = stripped != local
    return stripped, alias_detected


def check_syntax(email: str) -> SyntaxCheckResult:
    """Full syntax check pipeline."""
    flags: list[str] = []

    # 1. Normalise to lowercase
    lower = email.lower().strip()

    # 2. Basic structure: exactly one @, non-empty parts
    if lower.count("@") != 1:
        return SyntaxCheckResult(passed=False, sub_status="syntax_error", flags=flags)
    at_index = lower.index("@")
    local = lower[:at_index]
    domain = lower[at_index + 1:]

    if len(local) == 0 or len(domain) == 0:
        return SyntaxCheckResult(passed=False, sub_status="syntax_error", flags=flags)

    # 3. Length checks
    if len(local) > 64:
        return SyntaxCheckResult(passed=False, sub_status="length_exceeded", flags=flags)
    if len(lower) > 254:
        return SyntaxCheckResult(passed=False, sub_status="length_exceeded", flags=flags)

    # 4. Dot rules on local part
    if local.startswith(".") or local.endswith("."):
        return SyntaxCheckResult(passed=False, sub_status="dot_rule_violation", flags=flags)
    if ".." in local:
        return SyntaxCheckResult(passed=False, sub_status="dot_rule_violation", flags=flags)

    # 5. Character validation on local part
    if not _LOCAL_RE.match(local):
        return SyntaxCheckResult(passed=False, sub_status="syntax_error", flags=flags)

    # 6. Domain format
    if " " in domain or not _DOMAIN_RE.match(domain) or "." not in domain:
        return SyntaxCheckResult(passed=False, sub_status="syntax_error", flags=flags)

    # 7. TLD check
    tld = domain.split(".")[-1] if "." in domain else ""
    if tld not in _tld_set:
        return SyntaxCheckResult(passed=False, sub_status="invalid_tld", flags=flags)

    # 8. Typo detection (flag only, never reject)
    did_you_mean: Optional[str] = None
    suggestion = _find_typo_suggestion(domain)
    if suggestion:
        did_you_mean = f"{local}@{suggestion}"
        flags.append("typo_suggestion")

    # 9. Gmail alias normalisation
    norm_local, alias_detected = _normalise_gmail(local, domain)
    if alias_detected:
        flags.append("alias_detected")
    normalised = f"{norm_local}@{domain}"

    return SyntaxCheckResult(
        passed=True, normalised=normalised, did_you_mean=did_you_mean, flags=flags
    )
