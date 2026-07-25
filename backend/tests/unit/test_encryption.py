"""AES encryption/decryption, key management."""

from app.core.encryption import decrypt_field, encrypt_field


def test_encrypt_decrypt():
    assert decrypt_field(encrypt_field("sensitive data")) == "sensitive data"


def test_different_ciphertexts():
    assert encrypt_field("same") != encrypt_field("same")
