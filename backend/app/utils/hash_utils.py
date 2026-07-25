"""SHA-256, HMAC, Argon2, salt utilities."""

import hashlib
import hmac
import os


def sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def hmac_sha256(data: str, key: str) -> str:
    return hmac.new(key.encode(), data.encode(), hashlib.sha256).hexdigest()


def generate_salt(length: int = 32) -> str:
    return os.urandom(length).hex()
