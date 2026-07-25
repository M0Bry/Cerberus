"""Rate limiting logic."""

from app.core.abuse_detector import AbuseDetector


def test_abuse_detection():
    det = AbuseDetector()
    for _ in range(11):
        det.record_failed_login("1.2.3.4", "test@test.com")
    assert det.is_ip_suspicious("1.2.3.4")
