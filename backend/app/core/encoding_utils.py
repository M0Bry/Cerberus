"""
Encoding Utils — Shared encoding/decoding utilities.

بيوفر:
- Base64 encoding/decoding (standard + URL-safe)
- URL encoding/decoding
- HTML entity encoding/decoding
- Hex encoding/decoding
- Unicode escape encoding/decoding
- ROT13
- Multi-layer auto-decode
- Encoding detection
- Risk scoring for encoded payloads

الفكرة:
- مكتبة مساعدة بتُستخدم من كل ملفات Tier 2
- بسيطة، سريعة، بدون dependencies خارجية
- error-safe (بترجع None بدل ما ترمي exception)

الاستخدام:
- input_validator.py
- payload_decoder.py
- heuristic_scorer.py
- ml_payload_detector.py
- أي ملف محتاج encoding/decoding
"""

import base64
import binascii
import codecs
import html
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

import structlog

logger = structlog.get_logger()


class EncodingUtils:
    """
    Encoding/Decoding Utilities.

    كل الدوال بترجع None لو فشلت بدل ما ترمي exception.
    """

    # ─── Config ────────────────────────────────────────────
    MAX_DECODE_LAYERS = 5       # حد أقصى للـ multi-layer decode
    MAX_INPUT_SIZE = 100_000    # 100 KB

    # ─── Suspicious Patterns after decoding ───────────────
    SUSPICIOUS_PATTERNS = [
        r"<script",
        r"javascript:",
        r"onerror\s*=",
        r"onload\s*=",
        r"union\s+select",
        r"drop\s+table",
        r"insert\s+into",
        r"delete\s+from",
        r"\.\./",
        r"\.\.\\",
        r"/etc/passwd",
        r"cmd\.exe",
        r"powershell",
        r"eval\s*\(",
        r"exec\s*\(",
        r"system\s*\(",
    ]

    # ─── Pattern for detecting encoded strings ────────────
    BASE64_PATTERN = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
    BASE64_URL_PATTERN = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")
    HEX_PATTERN = re.compile(r"^(0x)?[0-9a-fA-F]+$")
    URL_PATTERN = re.compile(r"%[0-9a-fA-F]{2}")
    HTML_ENTITY_PATTERN = re.compile(r"&[a-zA-Z]+;|&#\d+;|&#x[0-9a-fA-F]+;")
    UNICODE_ESCAPE_PATTERN = re.compile(r"\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}")

    # ═══════════════════════════════════════════════════════
    #  Base64
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def b64_encode(data: str) -> Optional[str]:
        """بترمز النص لـ Base64."""
        try:
            if not isinstance(data, str):
                data = str(data)
            return base64.b64encode(data.encode("utf-8")).decode("ascii")
        except Exception as e:
            logger.debug("b64_encode_failed", error=str(e))
            return None

    @staticmethod
    def b64_decode(data: str) -> Optional[str]:
        """بتفك Base64."""
        if not data:
            return None

        try:
            # جرب standard base64
            padding = "=" * (-len(data) % 4)
            decoded = base64.b64decode(data + padding, validate=False)
            return decoded.decode("utf-8", errors="replace")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            pass

        # جرب URL-safe base64
        try:
            padding = "=" * (-len(data) % 4)
            decoded = base64.urlsafe_b64decode(data + padding)
            return decoded.decode("utf-8", errors="replace")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            return None

    # ═══════════════════════════════════════════════════════
    #  URL Encoding
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def url_encode(data: str, safe: str = "") -> Optional[str]:
        """بترمز النص لـ URL encoding."""
        try:
            if not isinstance(data, str):
                data = str(data)
            return urllib.parse.quote(data, safe=safe)
        except Exception as e:
            logger.debug("url_encode_failed", error=str(e))
            return None

    @staticmethod
    def url_decode(data: str) -> Optional[str]:
        """بتفك URL encoding."""
        if not data:
            return None
        try:
            return urllib.parse.unquote(data)
        except Exception as e:
            logger.debug("url_decode_failed", error=str(e))
            return None

    @staticmethod
    def url_decode_plus(data: str) -> Optional[str]:
        """بتفك URL encoding مع تحويل + لـ space."""
        if not data:
            return None
        try:
            return urllib.parse.unquote_plus(data)
        except Exception as e:
            logger.debug("url_decode_plus_failed", error=str(e))
            return None

    # ═══════════════════════════════════════════════════════
    #  HTML Entities
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def html_encode(data: str) -> Optional[str]:
        """بترمز HTML entities."""
        try:
            if not isinstance(data, str):
                data = str(data)
            return html.escape(data)
        except Exception as e:
            logger.debug("html_encode_failed", error=str(e))
            return None

    @staticmethod
    def html_decode(data: str) -> Optional[str]:
        """بتفك HTML entities."""
        if not data:
            return None
        try:
            return html.unescape(data)
        except Exception as e:
            logger.debug("html_decode_failed", error=str(e))
            return None

    # ═══════════════════════════════════════════════════════
    #  Hex
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def hex_encode(data: str) -> Optional[str]:
        """بترمز النص لـ Hex."""
        try:
            if not isinstance(data, str):
                data = str(data)
            return data.encode("utf-8").hex()
        except Exception as e:
            logger.debug("hex_encode_failed", error=str(e))
            return None

    @staticmethod
    def hex_decode(data: str) -> Optional[str]:
        """بتفك Hex."""
        if not data:
            return None

        try:
            clean = data.strip()
            if clean.startswith("0x") or clean.startswith("0X"):
                clean = clean[2:]

            # لازم يكون عدد زوجي
            if len(clean) % 2 != 0:
                clean = "0" + clean

            decoded = bytes.fromhex(clean)
            return decoded.decode("utf-8", errors="replace")
        except (ValueError, UnicodeDecodeError):
            return None

    # ═══════════════════════════════════════════════════════
    #  Unicode Escapes
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def unicode_escape_decode(data: str) -> Optional[str]:
        """
        بتفك Unicode escape sequences.

        مثال: \\u0041 → A
              \\x41 → A
        """
        if not data:
            return None
        try:
            return codecs.decode(data, "unicode_escape")
        except (UnicodeDecodeError, ValueError):
            return None

    @staticmethod
    def unicode_escape_encode(data: str) -> Optional[str]:
        """بترمز لـ Unicode escape."""
        try:
            if not isinstance(data, str):
                data = str(data)
            return codecs.encode(data, "unicode_escape").decode("ascii")
        except Exception as e:
            logger.debug("unicode_escape_encode_failed", error=str(e))
            return None

    # ═══════════════════════════════════════════════════════
    #  ROT13
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def rot13(data: str) -> Optional[str]:
        """ROT13 — نفس الدالة للـ encode والـ decode."""
        if not data:
            return None
        try:
            return codecs.encode(data, "rot_13")
        except Exception as e:
            logger.debug("rot13_failed", error=str(e))
            return None

    # ═══════════════════════════════════════════════════════
    #  Detection
    # ═══════════════════════════════════════════════════════

    @classmethod
    def looks_like_base64(cls, data: str) -> bool:
        """بيكشف لو النص شبه Base64."""
        if not data or len(data) < 4:
            return False
        if len(data) % 4 != 0 and "=" not in data:
            return False
        return bool(cls.BASE64_PATTERN.match(data))

    @classmethod
    def looks_like_base64_url(cls, data: str) -> bool:
        """بيكشف لو النص شبه Base64 URL-safe."""
        if not data or len(data) < 4:
            return False
        return bool(cls.BASE64_URL_PATTERN.match(data))

    @classmethod
    def looks_like_hex(cls, data: str) -> bool:
        """بيكشف لو النص شبه Hex."""
        if not data or len(data) < 4:
            return False
        clean = data.replace("0x", "").replace("0X", "")
        return bool(cls.HEX_PATTERN.match(clean)) and len(clean) % 2 == 0

    @classmethod
    def looks_like_url_encoded(cls, data: str) -> bool:
        """بيكشف لو النص فيه URL encoding."""
        if not data:
            return False
        return bool(cls.URL_PATTERN.search(data))

    @classmethod
    def looks_like_html_encoded(cls, data: str) -> bool:
        """بيكشف لو النص فيه HTML entities."""
        if not data:
            return False
        return bool(cls.HTML_ENTITY_PATTERN.search(data))

    @classmethod
    def looks_like_unicode_escape(cls, data: str) -> bool:
        """بيكشف لو النص فيه Unicode escapes."""
        if not data:
            return False
        return bool(cls.UNICODE_ESCAPE_PATTERN.search(data))

    @classmethod
    def detect_encoding_type(cls, data: str) -> Optional[str]:
        """
        بيكشف نوع التشفير المحتمل.

        Returns:
            "base64" | "base64_url" | "hex" | "url" |
            "html" | "unicode" | None
        """
        if not data:
            return None

        # ترتيب الأولويات مهم
        if cls.looks_like_url_encoded(data):
            return "url"
        if cls.looks_like_html_encoded(data):
            return "html"
        if cls.looks_like_unicode_escape(data):
            return "unicode"
        if cls.looks_like_hex(data):
            return "hex"
        if cls.looks_like_base64(data):
            return "base64"
        if cls.looks_like_base64_url(data):
            return "base64_url"

        return None

    # ═══════════════════════════════════════════════════════
    #  Multi-Layer Auto-Decode
    # ═══════════════════════════════════════════════════════

    @classmethod
    def auto_decode(
        cls,
        data: str,
        max_layers: Optional[int] = None,
    ) -> Tuple[str, List[str], int]:
        """
        بتفك التشفير تلقائياً طبقة بطبقة.

        Args:
            data: النص المشفر
            max_layers: حد أقصى للطبقات

        Returns:
            (النص المفكوك, قائمة الطبقات, عدد الطبقات)
        """
        if not data:
            return data, [], 0

        max_layers = max_layers or cls.MAX_DECODE_LAYERS
        layers: List[str] = []
        current = data

        for _ in range(max_layers):
            encoding_type = cls.detect_encoding_type(current)

            if not encoding_type:
                break

            decoded = cls._decode_by_type(current, encoding_type)

            # لو التفكيك فشل أو رجع نفس النص → وقف
            if not decoded or decoded == current:
                break

            layers.append(encoding_type)
            current = decoded

            # حد أقصى للحجم
            if len(current) > cls.MAX_INPUT_SIZE:
                break

        return current, layers, len(layers)

    @classmethod
    def _decode_by_type(cls, data: str, encoding_type: str) -> Optional[str]:
        """بتفك حسب النوع."""
        if encoding_type == "base64":
            return cls.b64_decode(data)
        if encoding_type == "base64_url":
            return cls.b64_decode(data)
        if encoding_type == "hex":
            return cls.hex_decode(data)
        if encoding_type == "url":
            return cls.url_decode_plus(data)
        if encoding_type == "html":
            return cls.html_decode(data)
        if encoding_type == "unicode":
            return cls.unicode_escape_decode(data)
        return None

    # ═══════════════════════════════════════════════════════
    #  Risk Scoring
    # ═══════════════════════════════════════════════════════

    @classmethod
    def score_encoded_payload(
        cls,
        decoded: str,
        layers: int = 0,
    ) -> Dict[str, Any]:
        """
        بيعمل score للنص المفكوك.

        Returns:
            dict فيه:
            - risk_score: 0-100
            - is_suspicious: bool
            - patterns_found: list
            - layers_decoded: int
        """
        if not decoded:
            return {
                "risk_score": 0,
                "is_suspicious": False,
                "patterns_found": [],
                "layers_decoded": layers,
            }

        patterns_found: List[str] = []

        # فحص الأنماط المشبوهة
        decoded_lower = decoded.lower()
        for pattern in cls.SUSPICIOUS_PATTERNS:
            if re.search(pattern, decoded_lower, re.IGNORECASE):
                patterns_found.append(pattern)

        # احسب الـ score
        score = 0

        # كل نمط مشبوه = 20 نقطة
        score += len(patterns_found) * 20

        # كل طبقة تشفير = 10 نقاط
        # (الـ obfuscation نفسها مشبوهة)
        score += layers * 10

        # نص طويل مشفر = مشبوه
        if len(decoded) > 1000:
            score += 10

        # لو فيه pattern مشبوه + طبقة تشفير → زوّد bonus
        # لأن الإخفاء المتعمد = نية سيئة
        if patterns_found and layers > 0:
            score += 10

        score = min(score, 100)

        return {
            "risk_score": score,
            "is_suspicious": score >= 30,
            "patterns_found": patterns_found,
            "layers_decoded": layers,
        }

    # ═══════════════════════════════════════════════════════
    #  High-Level Helpers
    # ═══════════════════════════════════════════════════════

    @classmethod
    def analyze(cls, data: str) -> Dict[str, Any]:
        """
        تحليل شامل للنص.

        Returns:
            dict فيه:
            - original: النص الأصلي
            - decoded: النص المفكوك
            - encoding_type: نوع التشفير المكتشف
            - layers: عدد الطبقات
            - risk_score: 0-100
            - is_suspicious: bool
            - patterns_found: list
        """
        if not data:
            return {
                "original": data,
                "decoded": data,
                "encoding_type": None,
                "layers": 0,
                "risk_score": 0,
                "is_suspicious": False,
                "patterns_found": [],
            }

        # 1. كشف النوع
        encoding_type = cls.detect_encoding_type(data)

        # 2. Auto-decode
        decoded, layer_names, layers = cls.auto_decode(data)

        # 3. Risk scoring
        score_result = cls.score_encoded_payload(decoded, layers)

        return {
            "original": data,
            "decoded": decoded,
            "encoding_type": encoding_type,
            "layer_types": layer_names,
            "layers": layers,
            "risk_score": score_result["risk_score"],
            "is_suspicious": score_result["is_suspicious"],
            "patterns_found": score_result["patterns_found"],
        }

    # ═══════════════════════════════════════════════════════
    #  Safe Encoding
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def safe_encode(data: str, encoding: str = "utf-8") -> Optional[str]:
        """
        بتعمل encode آمن.

        بتتعامل مع الأخطاء بدون exceptions.
        """
        if not isinstance(data, str):
            return None
        try:
            return data.encode(encoding, errors="replace").decode(encoding)
        except (UnicodeDecodeError, LookupError):
            return None

    @staticmethod
    def normalize_whitespace(data: str) -> str:
        """بتوحد المسافات."""
        if not data:
            return ""
        return re.sub(r"\s+", " ", data).strip()


# ─── Standalone functions (للـ convenience) ─────────────

def b64_decode(data: str) -> Optional[str]:
    """Shortcut for EncodingUtils.b64_decode."""
    return EncodingUtils.b64_decode(data)


def b64_encode(data: str) -> Optional[str]:
    """Shortcut for EncodingUtils.b64_encode."""
    return EncodingUtils.b64_encode(data)


def url_decode(data: str) -> Optional[str]:
    """Shortcut for EncodingUtils.url_decode."""
    return EncodingUtils.url_decode(data)


def url_encode(data: str) -> Optional[str]:
    """Shortcut for EncodingUtils.url_encode."""
    return EncodingUtils.url_encode(data)


def hex_decode(data: str) -> Optional[str]:
    """Shortcut for EncodingUtils.hex_decode."""
    return EncodingUtils.hex_decode(data)


def hex_encode(data: str) -> Optional[str]:
    """Shortcut for EncodingUtils.hex_encode."""
    return EncodingUtils.hex_encode(data)


def html_decode(data: str) -> Optional[str]:
    """Shortcut for EncodingUtils.html_decode."""
    return EncodingUtils.html_decode(data)


def html_encode(data: str) -> Optional[str]:
    """Shortcut for EncodingUtils.html_encode."""
    return EncodingUtils.html_encode(data)


def auto_decode(data: str) -> Tuple[str, List[str], int]:
    """Shortcut for EncodingUtils.auto_decode."""
    return EncodingUtils.auto_decode(data)


def detect_encoding_type(data: str) -> Optional[str]:
    """Shortcut for EncodingUtils.detect_encoding_type."""
    return EncodingUtils.detect_encoding_type(data)


def analyze(data: str) -> Dict[str, Any]:
    """Shortcut for EncodingUtils.analyze."""
    return EncodingUtils.analyze(data)