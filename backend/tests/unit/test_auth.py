"""Password hashing, JWT encode/decode, OTP validation."""

import hashlib
import re
from datetime import datetime

from app.core.security import (
    create_access_token,
    decode_token,
    generate_digital_signature,
    generate_otp,
    hash_otp,
    hash_password,
    verify_otp,
    verify_password,
)


def test_hash_and_verify():
    assert verify_password("test", hash_password("test"))


def test_wrong_password():
    assert not verify_password("wrong", hash_password("test"))


def test_jwt_roundtrip():
    token = create_access_token("user1")
    payload = decode_token(token)
    assert payload is not None
    assert payload["sub"] == "user1"


def test_otp_generation():
    otp = generate_otp()
    assert len(otp) == 6
    assert otp.isdigit()


def test_otp_hash_verify():
    assert verify_otp("123456", hash_otp("123456"))


def test_otp_hash_salted_per_record():
    """Hardened format: 'sha256$<salt>$<digest>' with a unique salt per record,
    so precomputation attacks cost per record instead of per batch."""
    h1 = hash_otp("123456")
    h2 = hash_otp("123456")
    assert h1.startswith("sha256$") and h1.count("$") == 2
    assert h1 != h2  # different salts
    assert verify_otp("123456", h1) and verify_otp("123456", h2)
    assert not verify_otp("654321", h1)


def test_otp_legacy_unsalted_row_still_verifies():
    """Rows written before hardening (bare 64-hex SHA-256) keep working."""
    legacy = hashlib.sha256(b"999888").hexdigest()
    assert verify_otp("999888", legacy)
    assert not verify_otp("000111", legacy)


def test_digital_signature_format():
    ts = datetime(2026, 1, 1, 12, 0, 0)
    sig = generate_digital_signature("user-1", "ENG-001", ts)
    assert re.fullmatch(r"[0-9a-f]{64}", sig)
    assert sig == generate_digital_signature("user-1", "ENG-001", ts)
    assert sig != generate_digital_signature("user-2", "ENG-001", ts)
