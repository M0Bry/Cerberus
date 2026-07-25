"""
Abuse Detector — Detects brute force, credential stuffing, and flooding.
"""

import time

import structlog

logger = structlog.get_logger()


class AbuseDetector:
    """Detects abuse patterns using in-memory counters (Redis-backed in production)."""

    def __init__(self) -> None:
        self._failed_logins: dict[str, list[float]] = {}
        self._register_attempts: dict[str, list[float]] = {}
        self._verify_attempts: dict[str, list[float]] = {}

    def record_failed_login(self, ip: str, email: str) -> dict:
        key = f"{ip}:{email}"
        now = time.time()
        self._failed_logins.setdefault(key, []).append(now)
        # Keep only last hour
        cutoff = now - 3600
        self._failed_logins[key] = [
            t for t in self._failed_logins[key] if t > cutoff
        ]

        count = len(self._failed_logins[key])
        is_abuse = count >= 10
        is_lockout = count >= 5

        if is_abuse:
            logger.warning(
                "abuse_detected",
                type="brute_force",
                ip=ip,
                email=email,
                attempts=count,
            )

        return {
            "failed_attempts": count,
            "is_locked_out": is_lockout,
            "is_abuse": is_abuse,
            "lockout_remaining_seconds": 900 if is_lockout else 0,
        }

    def record_register_attempt(self, ip: str) -> dict:
        now = time.time()
        self._register_attempts.setdefault(ip, []).append(now)
        cutoff = now - 3600
        self._register_attempts[ip] = [
            t for t in self._register_attempts[ip] if t > cutoff
        ]
        count = len(self._register_attempts[ip])
        return {"attempts": count, "is_abuse": count >= 5}

    def is_ip_suspicious(self, ip: str) -> bool:
        now = time.time()
        cutoff = now - 3600
        failed = len(
            [t for t in self._failed_logins.get(f"{ip}:", []) if t > cutoff]
        )
        return failed >= 20
