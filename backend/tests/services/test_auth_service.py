"""
Auth Service Unit Tests.
"""

from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    generate_otp,
    hash_otp,
    hash_password,
    verify_otp,
    verify_password,
)


class TestPasswordHashing:
    def test_hash_and_verify(self):
        password = "SecurePass123!"
        hashed = hash_password(password)
        assert verify_password(password, hashed) is True

    def test_wrong_password_fails(self):
        hashed = hash_password("CorrectPassword")
        assert verify_password("WrongPassword", hashed) is False

    def test_different_hashes_for_same_password(self):
        password = "SamePassword"
        hash1 = hash_password(password)
        hash2 = hash_password(password)
        assert hash1 != hash2  # bcrypt uses unique salts


class TestOTP:
    def test_generate_otp_length(self):
        otp = generate_otp()
        assert len(otp) == 6
        assert otp.isdigit()

    def test_hash_and_verify_otp(self):
        otp = "123456"
        hashed = hash_otp(otp)
        assert verify_otp(otp, hashed) is True

    def test_wrong_otp_fails(self):
        hashed = hash_otp("123456")
        assert verify_otp("654321", hashed) is False


class TestJWT:
    def test_create_and_decode_access_token(self):
        token = create_access_token(subject="user123")
        payload = decode_token(token)
        assert payload is not None
        assert payload["sub"] == "user123"
        assert payload["type"] == "access"

    def test_create_and_decode_refresh_token(self):
        token = create_refresh_token(subject="user123")
        payload = decode_token(token)
        assert payload is not None
        assert payload["type"] == "refresh"

    def test_invalid_token_returns_none(self):
        payload = decode_token("invalid.token.here")
        assert payload is None

    def test_extra_data_in_token(self):
        token = create_access_token(
            subject="user123",
            extra_data={"role": "admin"},
        )
        payload = decode_token(token)
        assert payload["role"] == "admin"
