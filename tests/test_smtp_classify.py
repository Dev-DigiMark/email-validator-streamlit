"""Ported from backend/tests/checks/smtp.test.ts (classifySMTPResponse cases).

These need no network. The checkMailbox socket-mock cases from the TS suite are
covered instead by the guarded live script (scripts/smtp_live_check.py).
"""
from app.checks.smtp import classify_smtp_response


class TestClassifySMTPResponse:
    def test_250_smtp_confirmed_exists_true(self):
        r = classify_smtp_response(250, "250 OK", "mail.example.com")
        assert r["sub_status"] == "smtp_confirmed"
        assert r["exists"] is True

    def test_551_553_mailbox_not_found_exists_false(self):
        assert classify_smtp_response(551, "551 User not local", "mail.example.com")["sub_status"] == "mailbox_not_found"
        assert classify_smtp_response(553, "553 Mailbox name not allowed", "mail.example.com")["sub_status"] == "mailbox_not_found"

    def test_550_mailbox_keyword_not_found_exists_false(self):
        r = classify_smtp_response(550, "550 No such user here", "mail.example.com")
        assert r["sub_status"] == "mailbox_not_found"
        assert r["exists"] is False

    def test_550_ip_reputation_keyword_exists_null(self):
        r = classify_smtp_response(550, "550 IP blocked by reputation filter", "mail.example.com")
        assert r["sub_status"] == "ip_reputation_block"
        assert r["exists"] is None

    def test_550_policy_keyword_exists_null(self):
        r = classify_smtp_response(550, "550 Policy violation detected", "mail.example.com")
        assert r["sub_status"] == "policy_rejection"
        assert r["exists"] is None

    def test_550_no_matching_keywords_ambiguous(self):
        r = classify_smtp_response(550, "550 Rejected", "mail.example.com")
        assert r["sub_status"] == "ambiguous_rejection"
        assert r["exists"] is None

    def test_421_greylisted(self):
        r = classify_smtp_response(421, "421 Try again later", "mail.example.com")
        assert r["sub_status"] == "greylisted"
        assert r["exists"] is None

    def test_451_temp_error(self):
        assert classify_smtp_response(451, "451 Temporary failure", "mail.example.com")["sub_status"] == "temp_error"

    def test_452_without_mailbox_full_keyword_temp_error(self):
        # "Too many recipients" does not match any mailboxFull keyword
        assert classify_smtp_response(452, "452 Too many recipients", "mail.example.com")["sub_status"] == "temp_error"

    def test_452_with_mailbox_full_keyword_mailbox_full(self):
        assert classify_smtp_response(452, "452 Insufficient storage", "mail.example.com")["sub_status"] == "mailbox_full"

    def test_503_504_server_error(self):
        assert classify_smtp_response(503, "503 Bad sequence", "mail.example.com")["sub_status"] == "server_error"
        assert classify_smtp_response(504, "504 Unrecognized parameter", "mail.example.com")["sub_status"] == "server_error"
