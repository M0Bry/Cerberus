"""
CSRF Protection — Token generation + validation for state-changing requests.
"""

import hashlib
import hmac
import os
import time

from app.core.config import settings

_SECRET = settings.SECRET_KEY.encode()


def generate_csrf_token(session_id: str) -> str:
    """Generate a CSRF token bound to a session."""
    nonce = os.urandom(16).hex()
    timestamp = str(int(time.time()))
    payload = f"{session_id}:{timestamp}:{nonce}"
    signature = hmac.new(_SECRET, payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}:{signature}"


def validate_csrf_token(token: str, session_id: str, max_age: int = 3600) -> bool:
    """Validate a CSRF token against a session ID."""
    try:
        parts = token.split(":")
        if len(parts) != 4:
            return False
        sid, ts, nonce, sig = parts
        if sid != session_id:
            return False
        if time.time() - int(ts) > max_age:
            return False
        expected = hmac.new(_SECRET, f"{sid}:{ts}:{nonce}".encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, sig)
    except Exception:
        return False
