"""Encryption Utilities — AES-256-GCM, RSA, key rotation helpers."""

import hashlib
import hmac
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import settings


def generate_data_key() -> bytes:
    """Generate a new AES-256 data encryption key."""
    return os.urandom(32)


def encrypt_with_key(key: bytes, plaintext: str) -> bytes:
    """Encrypt data with a specific AES-256-GCM key."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return nonce + ct


def decrypt_with_key(key: bytes, ciphertext: bytes) -> str:
    """Decrypt data with a specific AES-256-GCM key."""
    aesgcm = AESGCM(key)
    nonce, ct = ciphertext[:12], ciphertext[12:]
    return aesgcm.decrypt(nonce, ct, None).decode()


def hmac_sign(data: str, key: str | None = None) -> str:
    """Sign data with HMAC-SHA256."""
    return hmac.new(
        (key or settings.SECRET_KEY).encode(),
        data.encode(),
        hashlib.sha256,
    ).hexdigest()


def hmac_verify(data: str, signature: str, key: str | None = None) -> bool:
    """Verify HMAC-SHA256 signature."""
    expected = hmac_sign(data, key)
    return hmac.compare_digest(expected, signature)
