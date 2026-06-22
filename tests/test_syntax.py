"""Ported from backend/tests/checks/syntax.test.ts — same cases, same expectations."""
from app.checks.syntax import check_syntax


class TestCheckSyntax:
    def test_accepts_dot_in_the_middle(self):
        r = check_syntax("usman.amir@domain.com")
        assert r.passed is True

    def test_rejects_leading_dot(self):
        r = check_syntax(".john@domain.com")
        assert r.passed is False
        assert r.sub_status == "dot_rule_violation"

    def test_rejects_trailing_dot(self):
        r = check_syntax("john.@domain.com")
        assert r.passed is False
        assert r.sub_status == "dot_rule_violation"

    def test_rejects_consecutive_dots(self):
        r = check_syntax("john..doe@domain.com")
        assert r.passed is False
        assert r.sub_status == "dot_rule_violation"

    def test_accepts_plus_tag_and_flags_alias_for_gmail(self):
        r = check_syntax("john+tag@gmail.com")
        assert r.passed is True
        assert "alias_detected" in r.flags

    def test_strips_dots_from_gmail_local_part_and_flags_alias(self):
        r = check_syntax("j.o.h.n@gmail.com")
        assert r.passed is True
        assert r.normalised == "john@gmail.com"
        assert "alias_detected" in r.flags

    def test_suggests_did_you_mean_for_gmial(self):
        r = check_syntax("user@gmial.com")
        assert r.passed is True
        assert r.did_you_mean == "user@gmail.com"

    def test_rejects_invalid_tld(self):
        r = check_syntax("user@domain.con")
        assert r.passed is False
        assert r.sub_status == "invalid_tld"

    def test_rejects_missing_at(self):
        r = check_syntax("nodomain.com")
        assert r.passed is False
        assert r.sub_status == "syntax_error"

    def test_rejects_double_at(self):
        r = check_syntax("user@@domain.com")
        assert r.passed is False
        assert r.sub_status == "syntax_error"

    def test_rejects_local_part_longer_than_64(self):
        local = "a" * 65
        r = check_syntax(f"{local}@domain.com")
        assert r.passed is False
        assert r.sub_status == "length_exceeded"

    def test_rejects_total_length_over_254(self):
        local = "a" * 64
        domain = "b" * 186 + ".com"
        r = check_syntax(f"{local}@{domain}")
        assert r.passed is False
        assert r.sub_status == "length_exceeded"

    def test_rejects_spaces_in_email(self):
        r = check_syntax("user name@domain.com")
        assert r.passed is False
