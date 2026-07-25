"""Immutable log chain verification."""

from datetime import datetime, timezone

from app.core.immutable_logs import compute_log_hash


def test_hash_deterministic():
    h1 = compute_log_hash(
        {"action": "test"},
        None,
        datetime(2026, 1, 1, tzinfo=timezone.utc),  # noqa: UP017
    )
    h2 = compute_log_hash(
        {"action": "test"},
        None,
        datetime(2026, 1, 1, tzinfo=timezone.utc),  # noqa: UP017
    )
    assert h1 == h2
