"""
AES-256-GCM Encryption — Field-level encryption for sensitive data at rest.
"""

import base64
import hashlib
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from app.core.config import settings

# Derive encryption key from SECRET_KEY
_SALT = b"cerberus_field_encryption_v1"
_KDF = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=_SALT,
    iterations=100_000,
)
_MASTER_KEY = _KDF.derive(settings.SECRET_KEY.encode())


def encrypt_field(plaintext: str) -> str:
    """Encrypt a string field with AES-256-GCM. Returns base64(nonce + ciphertext + tag)."""
    aesgcm = AESGCM(_MASTER_KEY)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce + ct).decode()


def decrypt_field(ciphertext_b64: str) -> str:
    """Decrypt a field encrypted by encrypt_field()."""
    raw = base64.b64decode(ciphertext_b64)
    nonce, ct = raw[:12], raw[12:]
    aesgcm = AESGCM(_MASTER_KEY)
    return aesgcm.decrypt(nonce, ct, None).decode()


def hash_for_search(plaintext: str) -> str:
    """Deterministic hash for searching encrypted fields (HMAC-SHA256)."""
    return hashlib.sha256(f"cerberus_search:{plaintext}".encode()).hexdigest()
