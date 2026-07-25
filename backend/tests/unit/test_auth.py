"""Password hashing, JWT encode/decode, OTP validation."""

from app.core.security import (
    create_access_token,
    decode_token,
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
