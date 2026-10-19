"""
Hash Utils — Shared hashing utilities.

بيوفر:
- MD5, SHA1, SHA256, SHA512 hashing
- HMAC (SHA256)
- Salted hashing
- File hashing (streaming for large files)
- Fuzzy hashing (for similarity)
- Constant-time comparison
- Password hash detection (bcrypt/argon2/pbkdf2)
- Hash type detection
- Short hashes (truncated)
- Checksum verification

الفكرة:
- مكتبة مساعدة بتُستخدم من كل ملفات Tier 2
- بسيطة، سريعة، بدون dependencies خارجية
- error-safe (بترجع None بدل ما ترمي exception)

الاستخدام:
- ml_payload_detector.py (signatures)
- ip_reputation.py (cache keys)
- whitelist_manager.py (API keys)
- credential_stuffing.py (password hashing)
- أي ملف محتاج hashing
"""

import hashlib
import hmac
import os
import re
import secrets
from typing import Any, Dict, List, Optional, Tuple

import structlog

logger = structlog.get_logger()


class HashUtils:
    """
    Hashing Utilities.

    كل الدوال بترجع None لو فشلت بدل ما ترمي exception.
    """

    # ─── Config ────────────────────────────────────────────
    FILE_CHUNK_SIZE = 8192      # 8 KB
    DEFAULT_SALT_LENGTH = 16
    SHORT_HASH_LENGTH = 8

    # ─── Password Hash Patterns ───────────────────────────
    BCRYPT_PATTERN = re.compile(r"^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$")
    ARGON2_PATTERN = re.compile(r"^\$argon2(id|i|d)\$")
    PBKDF2_PATTERN = re.compile(r"^\$pbkdf2-sha256\$")
    SHA512_CRYPT_PATTERN = re.compile(r"^\$6\$")
    MD5_CRYPT_PATTERN = re.compile(r"^\$1\$")
    SCRYPT_PATTERN = re.compile(r"^\$scrypt\$")

    # ═══════════════════════════════════════════════════════
    #  Basic Hashing
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def md5(data: str) -> Optional[str]:
        """MD5 hash (hex)."""
        try:
            if not isinstance(data, str):
                data = str(data)
            return hashlib.md5(data.encode("utf-8")).hexdigest()
        except Exception as e:
            logger.debug("md5_failed", error=str(e))
            return None

    @staticmethod
    def sha1(data: str) -> Optional[str]:
        """SHA1 hash (hex)."""
        try:
            if not isinstance(data, str):
                data = str(data)
            return hashlib.sha1(data.encode("utf-8")).hexdigest()
        except Exception as e:
            logger.debug("sha1_failed", error=str(e))
            return None

    @staticmethod
    def sha256(data: str) -> Optional[str]:
        """SHA256 hash (hex)."""
        try:
            if not isinstance(data, str):
                data = str(data)
            return hashlib.sha256(data.encode("utf-8")).hexdigest()
        except Exception as e:
            logger.debug("sha256_failed", error=str(e))
            return None

    @staticmethod
    def sha512(data: str) -> Optional[str]:
        """SHA512 hash (hex)."""
        try:
            if not isinstance(data, str):
                data = str(data)
            return hashlib.sha512(data.encode("utf-8")).hexdigest()
        except Exception as e:
            logger.debug("sha512_failed", error=str(e))
            return None

    @staticmethod
    def sha3_256(data: str) -> Optional[str]:
        """SHA3-256 hash (hex)."""
        try:
            if not isinstance(data, str):
                data = str(data)
            return hashlib.sha3_256(data.encode("utf-8")).hexdigest()
        except Exception as e:
            logger.debug("sha3_256_failed", error=str(e))
            return None

    @classmethod
    def hash_by_algorithm(
        cls,
        data: str,
        algorithm: str = "sha256",
    ) -> Optional[str]:
        """
        Hash بأي algorithm.

        Args:
            data: النص
            algorithm: md5, sha1, sha256, sha512, sha3_256
        """
        algorithms = {
            "md5": cls.md5,
            "sha1": cls.sha1,
            "sha256": cls.sha256,
            "sha512": cls.sha512,
            "sha3_256": cls.sha3_256,
        }
        func = algorithms.get(algorithm.lower())
        if not func:
            return None
        return func(data)

    # ═══════════════════════════════════════════════════════
    #  Short Hashes
    # ═══════════════════════════════════════════════════════

    @classmethod
    def short_hash(
        cls,
        data: str,
        length: int = SHORT_HASH_LENGTH,
        algorithm: str = "sha256",
    ) -> Optional[str]:
        """
        Hash مختصر (للـ cache keys و IDs).
        """
        full = cls.hash_by_algorithm(data, algorithm)
        if not full:
            return None
        return full[:length]

    @staticmethod
    def stable_id(data: str, prefix: str = "") -> str:
        """
        بيعمل ID ثابت من النص.

        مفيد للـ cache keys و deduplication.
        """
        h = HashUtils.short_hash(data, length=16)
        if not h:
            return ""
        return f"{prefix}{h}" if prefix else h

    # ═══════════════════════════════════════════════════════
    #  HMAC
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def hmac_sha256(data: str, key: str) -> Optional[str]:
        """HMAC-SHA256."""
        if not data or not key:
            return None
        try:
            return hmac.new(
                key.encode("utf-8"),
                data.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
        except Exception as e:
            logger.debug("hmac_sha256_failed", error=str(e))
            return None

    @staticmethod
    def hmac_verify(data: str, key: str, signature: str) -> bool:
        """
        بيتحقق من HMAC signature (constant-time).
        """
        if not data or not key or not signature:
            return False

        expected = HashUtils.hmac_sha256(data, key)
        if not expected:
            return False

        return HashUtils.constant_time_compare(expected, signature)

    # ═══════════════════════════════════════════════════════
    #  Salted Hashing
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def generate_salt(length: int = DEFAULT_SALT_LENGTH) -> str:
        """بيولّد salt عشوائي."""
        return secrets.token_hex(length)

    @classmethod
    def salted_hash(
        cls,
        data: str,
        salt: Optional[str] = None,
        algorithm: str = "sha256",
    ) -> Tuple[Optional[str], str]:
        """
        بيعمل hash مع salt.

        Returns:
            (hash, salt) — لو salt مش متبعت، بيتولّد جديد.
        """
        if not data:
            return None, salt or ""

        if not salt:
            salt = cls.generate_salt()

        combined = f"{salt}:{data}"
        hashed = cls.hash_by_algorithm(combined, algorithm)

        return hashed, salt

    @classmethod
    def verify_salted_hash(
        cls,
        data: str,
        salt: str,
        expected_hash: str,
        algorithm: str = "sha256",
    ) -> bool:
        """بيتحقق من salted hash."""
        if not data or not salt or not expected_hash:
            return False

        computed, _ = cls.salted_hash(data, salt, algorithm)
        if not computed:
            return False

        return cls.constant_time_compare(computed, expected_hash)

    # ═══════════════════════════════════════════════════════
    #  File Hashing
    # ═══════════════════════════════════════════════════════

    @classmethod
    def hash_file(
        cls,
        file_path: str,
        algorithm: str = "sha256",
    ) -> Optional[str]:
        """
        بيعمل hash لملف (streaming).

        مفيد للملفات الكبيرة.
        """
        algorithms = {
            "md5": hashlib.md5,
            "sha1": hashlib.sha1,
            "sha256": hashlib.sha256,
            "sha512": hashlib.sha512,
        }

        hasher_class = algorithms.get(algorithm.lower())
        if not hasher_class:
            return None

        try:
            hasher = hasher_class()
            with open(file_path, "rb") as f:
                while chunk := f.read(cls.FILE_CHUNK_SIZE):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except (OSError, IOError) as e:
            logger.debug("hash_file_failed", error=str(e), path=file_path)
            return None

    @classmethod
    def hash_bytes(
        cls,
        data: bytes,
        algorithm: str = "sha256",
    ) -> Optional[str]:
        """بيعمل hash لـ bytes."""
        algorithms = {
            "md5": hashlib.md5,
            "sha1": hashlib.sha1,
            "sha256": hashlib.sha256,
            "sha512": hashlib.sha512,
        }
        hasher_class = algorithms.get(algorithm.lower())
        if not hasher_class:
            return None

        try:
            return hasher_class(data).hexdigest()
        except Exception as e:
            logger.debug("hash_bytes_failed", error=str(e))
            return None

    # ═══════════════════════════════════════════════════════
    #  Fuzzy Hashing (Similarity)
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def fuzzy_hash(data: str, token_size: int = 3) -> Optional[str]:
        """
        بيعمل fuzzy hash بسيط (shingle-based).

        مفيد لمقارنة النصوص المتشابهة (زي ssdeep بس أبسط).
        """
        if not data or len(data) < token_size:
            return None

        try:
            # قسّم لـ shingles
            shingles = [
                data[i:i + token_size]
                for i in range(len(data) - token_size + 1)
            ]

            if not shingles:
                return None

            # hash كل shingle
            shingle_hashes = set()
            for shingle in shingles:
                h = HashUtils.short_hash(shingle, length=8)
                if h:
                    shingle_hashes.add(h)

            # رتبهم وخد عينة
            sorted_hashes = sorted(shingle_hashes)
            return ":".join(sorted_hashes[:32])
        except Exception as e:
            logger.debug("fuzzy_hash_failed", error=str(e))
            return None

    @staticmethod
    def fuzzy_similarity(hash1: str, hash2: str) -> float:
        """
        بيحسب نسبة التشابه بين fuzzy hashes (0.0 - 1.0).
        """
        if not hash1 or not hash2:
            return 0.0

        set1 = set(hash1.split(":"))
        set2 = set(hash2.split(":"))

        if not set1 or not set2:
            return 0.0

        intersection = set1 & set2
        union = set1 | set2

        return len(intersection) / len(union) if union else 0.0

    # ═══════════════════════════════════════════════════════
    #  Constant-Time Comparison
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def constant_time_compare(a: str, b: str) -> bool:
        """
        مقارنة آمنة (constant-time).

        بتمنع timing attacks.
        """
        if not isinstance(a, str) or not isinstance(b, str):
            return False

        try:
            return hmac.compare_digest(a, b)
        except Exception:
            return False

    # ═══════════════════════════════════════════════════════
    #  Password Hash Detection
    # ═══════════════════════════════════════════════════════

    @classmethod
    def detect_password_hash_type(cls, hash_str: str) -> Optional[str]:
        """
        بيكشف نوع الـ password hash.

        Returns:
            "bcrypt" | "argon2" | "pbkdf2" | "scrypt" |
            "sha512_crypt" | "md5_crypt" | None
        """
        if not hash_str:
            return None

        if cls.BCRYPT_PATTERN.match(hash_str):
            return "bcrypt"
        if cls.ARGON2_PATTERN.match(hash_str):
            return "argon2"
        if cls.PBKDF2_PATTERN.match(hash_str):
            return "pbkdf2"
        if cls.SCRYPT_PATTERN.match(hash_str):
            return "scrypt"
        if cls.SHA512_CRYPT_PATTERN.match(hash_str):
            return "sha512_crypt"
        if cls.MD5_CRYPT_PATTERN.match(hash_str):
            return "md5_crypt"

        return None

    @classmethod
    def is_strong_password_hash(cls, hash_str: str) -> bool:
        """
        بيتحقق لو الـ hash قوي.

        القوي: bcrypt, argon2, scrypt, pbkdf2
        """
        strong_types = {"bcrypt", "argon2", "scrypt", "pbkdf2"}
        hash_type = cls.detect_password_hash_type(hash_str)
        return hash_type in strong_types

    @classmethod
    def is_weak_password_hash(cls, hash_str: str) -> bool:
        """بيتحقق لو الـ hash ضعيف."""
        weak_types = {"md5_crypt", "sha512_crypt"}
        hash_type = cls.detect_password_hash_type(hash_str)
        return hash_type in weak_types

    # ═══════════════════════════════════════════════════════
    #  Hash Type Detection
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def detect_hash_type(hash_str: str) -> Optional[str]:
        """
        بيكشف نوع الـ hash من طوله وشكله.

        Returns:
            "md5" | "sha1" | "sha256" | "sha512" | None
        """
        if not hash_str:
            return None

        # لازم يكون hex
        if not re.match(r"^[a-fA-F0-9]+$", hash_str):
            return None

        length = len(hash_str)

        if length == 32:
            return "md5"
        if length == 40:
            return "sha1"
        if length == 64:
            return "sha256"
        if length == 128:
            return "sha512"

        return None

    # ═══════════════════════════════════════════════════════
    #  Checksums
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def crc32(data: str) -> Optional[str]:
        """CRC32 checksum (hex)."""
        try:
            import zlib
            if not isinstance(data, str):
                data = str(data)
            crc = zlib.crc32(data.encode("utf-8"))
            return format(crc & 0xFFFFFFFF, "08x")
        except Exception as e:
            logger.debug("crc32_failed", error=str(e))
            return None

    @classmethod
    def verify_checksum(
        cls,
        data: str,
        expected: str,
        algorithm: str = "sha256",
    ) -> bool:
        """بيتحقق من checksum."""
        computed = cls.hash_by_algorithm(data, algorithm)
        if not computed:
            return False
        return cls.constant_time_compare(computed, expected.lower())

    # ═══════════════════════════════════════════════════════
    #  High-Level Helpers
    # ═══════════════════════════════════════════════════════

    @classmethod
    def fingerprint(cls, data: str) -> Dict[str, Any]:
        """
        بيعمل "بصمة" شاملة للنص.

        Returns:
            dict فيه md5, sha1, sha256, sha512, length
        """
        if not data:
            return {
                "md5": None,
                "sha1": None,
                "sha256": None,
                "sha512": None,
                "length": 0,
            }

        return {
            "md5": cls.md5(data),
            "sha1": cls.sha1(data),
            "sha256": cls.sha256(data),
            "sha512": cls.sha512(data),
            "length": len(data),
        }

    @staticmethod
    def random_token(length: int = 32) -> str:
        """بيولّد token عشوائي آمن."""
        return secrets.token_urlsafe(length)

    @staticmethod
    def random_hex(length: int = 32) -> str:
        """بيولّد hex عشوائي."""
        return secrets.token_hex(length // 2)


# ─── Standalone functions (للـ convenience) ─────────────

def md5(data: str) -> Optional[str]:
    """Shortcut for HashUtils.md5."""
    return HashUtils.md5(data)


def sha1(data: str) -> Optional[str]:
    """Shortcut for HashUtils.sha1."""
    return HashUtils.sha1(data)


def sha256(data: str) -> Optional[str]:
    """Shortcut for HashUtils.sha256."""
    return HashUtils.sha256(data)


def sha512(data: str) -> Optional[str]:
    """Shortcut for HashUtils.sha512."""
    return HashUtils.sha512(data)


def short_hash(data: str, length: int = 8) -> Optional[str]:
    """Shortcut for HashUtils.short_hash."""
    return HashUtils.short_hash(data, length)


def hmac_sha256(data: str, key: str) -> Optional[str]:
    """Shortcut for HashUtils.hmac_sha256."""
    return HashUtils.hmac_sha256(data, key)


def hash_file(file_path: str, algorithm: str = "sha256") -> Optional[str]:
    """Shortcut for HashUtils.hash_file."""
    return HashUtils.hash_file(file_path, algorithm)


def random_token(length: int = 32) -> str:
    """Shortcut for HashUtils.random_token."""
    return HashUtils.random_token(length)


def fingerprint(data: str) -> Dict[str, Any]:
    """Shortcut for HashUtils.fingerprint."""
    return HashUtils.fingerprint(data)