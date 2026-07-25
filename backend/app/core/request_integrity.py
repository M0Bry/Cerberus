"""
Request Integrity — Request signing + integrity verification.
"""

import hashlib
import hmac
import time

from app.core.config import settings

_SECRET = settings.SECRET_KEY.encode()


def sign_request(method: str, path: str, timestamp: str, body_hash: str) -> str:
    """Sign a request with HMAC-SHA256."""
    payload = f"{method}:{path}:{timestamp}:{body_hash}"
    return hmac.new(_SECRET, payload.encode(), hashlib.sha256).hexdigest()


def verify_request_signature(
    method: str, path: str, timestamp: str, body_hash: str,
    signature: str, max_age: int = 300,
) -> bool:
    """Verify a request signature and check timestamp freshness."""
    try:
        if abs(time.time() - int(timestamp)) > max_age:
            return False
        expected = sign_request(method, path, timestamp, body_hash)
        return hmac.compare_digest(expected, signature)
    except Exception:
        return False
