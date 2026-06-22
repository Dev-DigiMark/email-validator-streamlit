"""Ported from backend/tests/checks/lists.test.ts — same cases, same expectations."""
from app.checks.lists import (
    check_role,
    has_spam_trap_keyword,
    is_disposable,
    is_duplicate,
    is_free_provider,
)


class TestIsDisposable:
    def test_identifies_mailinator_as_disposable(self):
        assert is_disposable("mailinator.com") is True

    def test_does_not_flag_gmail_as_disposable(self):
        assert is_disposable("gmail.com") is False


class TestIsFreeProvider:
    def test_identifies_gmail_as_free_provider(self):
        assert is_free_provider("gmail.com") is True

    def test_does_not_flag_mailinator_as_free_provider(self):
        assert is_free_provider("mailinator.com") is False


class TestCheckRole:
    def test_rejects_noreply(self):
        r = check_role("noreply")
        assert r["rejected"] is True
        assert r["flagged"] is False

    def test_flags_admin_but_does_not_reject(self):
        r = check_role("admin")
        assert r["rejected"] is False
        assert r["flagged"] is True

    def test_flags_info_but_does_not_reject(self):
        r = check_role("info")
        assert r["rejected"] is False
        assert r["flagged"] is True

    def test_does_not_flag_regular_name(self):
        r = check_role("usman")
        assert r["rejected"] is False
        assert r["flagged"] is False


class TestHasSpamTrapKeyword:
    def test_detects_spam_keyword(self):
        assert has_spam_trap_keyword("spam") is True
        assert has_spam_trap_keyword("spamtest") is True

    def test_does_not_flag_regular_local_parts(self):
        assert has_spam_trap_keyword("usman") is False


class TestIsDuplicate:
    def test_returns_false_first_then_true_for_duplicate(self):
        seen: set[str] = set()
        assert is_duplicate("user@example.com", seen) is False
        assert is_duplicate("user@example.com", seen) is True

    def test_treats_distinct_emails_as_non_duplicates(self):
        seen: set[str] = set()
        assert is_duplicate("a@example.com", seen) is False
        assert is_duplicate("b@example.com", seen) is False
