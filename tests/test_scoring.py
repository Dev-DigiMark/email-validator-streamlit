"""Stage-4 scoring fidelity tests.

Crafted reserved results + dns/website/pattern inputs, asserting identical
scores and promote/demote verdicts to the TS scoreReservedShard / computeScore.
No network. DNS/website inputs are simple stand-ins exposing the same attrs the
porter reads (spf_found, dmarc_found, dkim_found, domain_blacklisted,
domain_age_days, has_website).
"""
from types import SimpleNamespace

from app.models import ValidationResult
from app.pipeline.scoring_core import ScoringThresholds, score_reserved_shard
from app.store.patterns import PatternSnapshot

THRESHOLDS = ScoringThresholds(promoteToValid=85, demoteToInvalid=25)


def _dns(**kw):
    base = dict(
        spf_found=False, dmarc_found=False, dkim_found=False,
        domain_blacklisted=False, domain_age_days=-1,
    )
    base.update(kw)
    return SimpleNamespace(**base)


def _website(has):
    return SimpleNamespace(has_website=has)


def _result(email, normalised, sub_status, **kw):
    base = dict(
        email=email, normalised=normalised, status="reserved",
        sub_status=sub_status, score=50, confidence="low", flags=[],
        is_free_provider=False, is_role_address=False, is_disposable=False,
        processing_stage=3, mx_record=None, smtp_provider=None,
    )
    base.update(kw)
    return ValidationResult(**base)


def _empty_snapshot():
    return PatternSnapshot(confirmedFormats={}, resolvedValid={}, resolveRates={}, bounceRates={})


def test_smtp_confirmed_strong_domain_promotes():
    r = _result(
        "john.smith@acme.com", "john.smith@acme.com", "smtp_confirmed",
        mx_record="aspmx.l.google.com",
    )
    dns = {"acme.com": _dns(spf_found=True, dmarc_found=True, dkim_found=True, domain_age_days=3000)}
    web = {"acme.com": _website(True)}
    pattern = PatternSnapshot(
        confirmedFormats={"acme.com": ["firstname.lastname"]},
        resolvedValid={"acme.com": 3},
        resolveRates={"acme.com": 0.9},
        bounceRates={"acme.com": 0.0},
    )

    out = score_reserved_shard([r], dns, web, pattern, THRESHOLDS)[0]
    # 50 +10 +15 +10 +10 +12 +8 +20 +15 = 150 -> clamp 100
    assert out.score == 100
    assert out.status == "valid"
    assert out.confidence == "medium"
    assert out.promoted_from_reserved is True
    assert out.processing_stage == 4


def test_no_mx_record_hard_demotes():
    r = _result("a@nomx.com", "a@nomx.com", "no_mx_record")
    out = score_reserved_shard([r], {}, {}, _empty_snapshot(), THRESHOLDS)[0]
    assert out.status == "invalid"
    assert out.score == 0
    assert out.confidence == "high"
    assert out.processing_stage == 4


def test_low_score_demotes_to_invalid():
    r = _result(
        "xq7z9k2@sketchy.tk", "xq7z9k2@sketchy.tk", "mailbox_not_found",
        mx_record="mail.sketchy.tk",
    )
    dns = {"sketchy.tk": _dns(domain_age_days=30, domain_blacklisted=True)}
    web = {"sketchy.tk": _website(False)}
    out = score_reserved_shard([r], dns, web, _empty_snapshot(), THRESHOLDS)[0]
    # 50 -25 -5 -20 -3 -30 = -33 -> clamp 0
    assert out.score == 0
    assert out.status == "invalid"
    assert out.confidence == "medium"
    assert out.demoted_from_reserved is True


def test_high_reputation_without_proof_stays_reserved():
    # Strong domain but no smtp_confirmed; allowReputationPromotion default False.
    r = _result(
        "john.smith@acme.com", "john.smith@acme.com", "ip_reputation_block",
        mx_record="aspmx.l.google.com",
    )
    dns = {"acme.com": _dns(spf_found=True, dmarc_found=True, dkim_found=True, domain_age_days=3000)}
    web = {"acme.com": _website(True)}
    pattern = PatternSnapshot(
        confirmedFormats={"acme.com": ["firstname.lastname"]},
        resolvedValid={"acme.com": 3},
        resolveRates={"acme.com": 0.9},
        bounceRates={"acme.com": 0.0},
    )
    out = score_reserved_shard([r], dns, web, pattern, THRESHOLDS)[0]
    # honestProvider -15 applied (not smtp_confirmed): 150 -15 = 135 -> clamp 100
    assert out.score == 100
    assert out.status == "reserved"  # neither promoted nor demoted
    assert out.promoted_from_reserved is None
    assert out.demoted_from_reserved is None


def test_breakdown_skips_zero_point_signals():
    # accept_all on a reputable MX: catchAllBusinessProvider is 0 pts -> omitted.
    r = _result(
        "sales@acme.com", "sales@acme.com", "accept_all",
        mx_record="aspmx.l.google.com", is_role_address=True,
    )
    dns = {"acme.com": _dns(domain_age_days=3000)}
    web = {"acme.com": _website(True)}
    out = score_reserved_shard([r], dns, web, _empty_snapshot(), THRESHOLDS)[0]
    signals = {b.signal for b in out.score_breakdown}
    assert "catchAllBusinessProvider" not in signals
    assert "roleAddress" in signals
    # accept_all is in NEVER_PROMOTE -> can never become valid
    assert out.status != "valid"
