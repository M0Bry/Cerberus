"""
Immutable Log Chain — Blockchain-inspired tamper-evident audit logs.

Each log entry's hash includes the previous entry's hash, creating
an append-only chain that detects tampering.
"""

import hashlib
import hmac
import json
from datetime import datetime

import structlog

from app.core.config import settings

logger = structlog.get_logger()

_HMAC_KEY = settings.SECRET_KEY.encode()


def compute_log_hash(
    content: dict,
    previous_hash: str | None,
    timestamp: datetime,
) -> str:
    """
    Compute SHA-256 hash for an immutable log entry.

    Hash = SHA256(content_json + previous_hash + timestamp_iso)
    """
    payload = (
        json.dumps(content, sort_keys=True)
        + (previous_hash or "GENESIS")
        + timestamp.isoformat()
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def sign_log(log_hash: str) -> str:
    """Sign a log hash with HMAC-SHA256 using the server secret."""
    return hmac.new(_HMAC_KEY, log_hash.encode(), hashlib.sha256).hexdigest()


def verify_log_chain(
    entries: list[dict],
) -> tuple[bool, list[str]]:
    """
    Verify the integrity of an immutable log chain.

    Returns:
        (is_valid, list_of_errors)
    """
    errors = []
    for i, entry in enumerate(entries):
        # Determine previous hash (GENESIS for first entry)
        prev_hash = None
        if i > 0:
            prev_hash = entries[i - 1]["log_hash"]

        expected_hash = compute_log_hash(
            content=entry["content"],
            previous_hash=prev_hash,
            timestamp=datetime.fromisoformat(entry["created_at"]),
        )
        if expected_hash != entry["log_hash"]:
            errors.append(f"Chain broken at index {i}: hash mismatch")

        # Verify HMAC signature
        expected_sig = sign_log(entry["log_hash"])
        if not hmac.compare_digest(expected_sig, entry.get("signature", "")):
            errors.append(f"Signature invalid at index {i}")

    return len(errors) == 0, errors
