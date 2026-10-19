"""Abuse detection (brute-force tracking) — 3-tier defense system.

The abuse layer is Redis-first with an in-memory fallback, and is
driven by the middleware's post-response correlation, so these tests
exercise the public async API of AbuseDetector directly.
"""

from app.core.abuse_detector import AbuseDetector
from app.core.config import settings


async def test_abuse_detection():
    """ABUSE_MAX_FAILED_LOGINS failed logins flag the IP; twice that
    hard-blocks it."""
    AbuseDetector.reset_all()

    for _ in range(settings.ABUSE_MAX_FAILED_LOGINS):
        await AbuseDetector.record_failed_login("1.2.3.4", "test@test.com")

    assert await AbuseDetector.is_abusive("1.2.3.4")
    assert not await AbuseDetector.is_blocked("1.2.3.4")

    # 5 more failures reach the hard-block threshold (5 * 2).
    for _ in range(settings.ABUSE_MAX_FAILED_LOGINS):
        await AbuseDetector.record_failed_login("1.2.3.4", "test@test.com")

    assert await AbuseDetector.is_blocked("1.2.3.4")

    # A clean IP is untouched.
    assert not await AbuseDetector.is_abusive("5.6.7.8")

    AbuseDetector.reset_all()


async def test_failed_login_counting_is_not_double_counted():
    """The per-IP counter is authoritative: one failed login must count
    as exactly ONE (the per-email forensic key must not be summed on
    top — that used to lock users out after only 3 wrong passwords)."""
    AbuseDetector.reset_all()

    for _ in range(settings.ABUSE_MAX_FAILED_LOGINS - 1):
        await AbuseDetector.record_failed_login("9.9.9.9", "victim@test.com")

    assert not await AbuseDetector.is_abusive("9.9.9.9")

    # The final (Nth) failure crosses the threshold — exactly at N.
    await AbuseDetector.record_failed_login("9.9.9.9", "victim@test.com")
    assert await AbuseDetector.is_abusive("9.9.9.9")

    AbuseDetector.reset_all()


async def test_manual_block_and_unblock():
    AbuseDetector.reset_all()
    await AbuseDetector.block_ip("8.8.8.8", duration=60)
    assert await AbuseDetector.is_blocked("8.8.8.8")
    await AbuseDetector.unblock_ip("8.8.8.8")
    assert not await AbuseDetector.is_blocked("8.8.8.8")
    AbuseDetector.reset_all()
