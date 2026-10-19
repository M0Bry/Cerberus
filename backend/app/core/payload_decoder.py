"""
Payload Decoder — Decodes payloads with multiple encoding schemes.

يفك تشفير الـ payload بـ 15 طريقة مختلفة عشان نمسك الهجمات المشفرة.

بيوفر:
- URL decode (single + double)
- Unicode decode (escape sequences)
- HTML entities decode
- Base64 decode
- Hex decode
- Octal decode
- Quoted-Printable decode
- Gzip/Deflate decompression
- ROT13 decode (optional)
- Reverse string (optional)
- Unicode normalization (NFKC, NFD)
- Mixed decoding (multi-layer)
"""

import base64
import codecs
import gzip
import html
import re
import urllib.parse
import zlib
from typing import Dict, List, Optional, Set

import structlog

logger = structlog.get_logger()


class PayloadDecoder:
    """
    كلاس لفك تشفير الـ payloads.

    بيوفر 15+ طريقة لفك التشفير.

    ملاحظة مهمة:
    - Clean Decoders: URL, HTML, Unicode, Base64, Hex, Octal, QP, Unicode Normalization
      → دايماً بتشتغل (لأنها طرق قياسية)
    - Mutation Decoders: ROT13, Reverse
      → اختيارية (لأنها بتلخبط النتيجة)
    """

    MAX_PAYLOAD_SIZE = 50_000
    MAX_VARIANTS = 50

    # ─── Main API ──────────────────────────────────────────

    @classmethod
    def decode_all(
        cls,
        value: str,
        max_depth: int = 3,
        include_mutations: bool = False,
    ) -> List[str]:
        """
        بيفك تشفير الـ payload بكل الطرق الممكنة.

        Args:
            value: الـ payload الأصلي
            max_depth: أقصى عمق للتشفير المتداخل (default: 3)
            include_mutations: لو True، يطبق ROT13 و Reverse كمان (default: False)

        Returns:
            List من الـ variants (الأصلي + كل الـ decoded versions)
            مرتبة حسب الأولوية (الأكثر احتمالاً أولاً)
        """
        if not isinstance(value, str) or not value:
            return [value] if value else []

        if len(value) > cls.MAX_PAYLOAD_SIZE:
            logger.warning("payload_too_large", size=len(value))
            return [value]

        variants: List[str] = [value]
        seen: Set[str] = {value}
        current_level = [value]

        for depth in range(max_depth):
            next_level: List[str] = []

            for payload in current_level:
                decoded = cls._decode_single_level(
                    payload, include_mutations=include_mutations
                )
                for d in decoded:
                    if d not in seen:
                        seen.add(d)
                        next_level.append(d)

            if not next_level:
                break

            variants.extend(next_level)
            current_level = next_level

            if len(variants) >= cls.MAX_VARIANTS:
                break

        return variants[: cls.MAX_VARIANTS]

    @classmethod
    def _decode_single_level(
        cls,
        value: str,
        include_mutations: bool = False,
    ) -> List[str]:
        """
        بيفك تشفير الـ payload مرة واحدة (كل الطرق).

        Args:
            value: الـ payload
            include_mutations: لو True، يطبق ROT13 و Reverse كمان

        Returns:
            List من الـ variants (مرتبة حسب الأولوية)
        """
        results: List[str] = []

        def _add(decoded: Optional[str]) -> None:
            """Helper: ضيف النتيجة لو جديدة"""
            if decoded and decoded != value and decoded not in results:
                results.append(decoded)

        # ─── Clean Decoders (الأولوية العالية) ───

        # 1. URL Decode (single)
        url_decoded = cls._url_decode(value)
        _add(url_decoded)

        # 2. URL Decode (double)
        if url_decoded:
            url_decoded_double = cls._url_decode(url_decoded)
            _add(url_decoded_double)

        # 3. HTML Entities
        _add(cls._html_decode(value))

        # 4. Unicode Escape
        _add(cls._unicode_decode(value))

        # 5. Base64
        _add(cls._base64_decode(value))

        # 6. Hex
        _add(cls._hex_decode(value))

        # 7. Octal
        _add(cls._octal_decode(value))

        # 8. Quoted-Printable
        _add(cls._quoted_printable_decode(value))

        # 9. Unicode Normalization (NFKC)
        _add(cls._unicode_normalize(value, "NFKC"))

        # 10. Unicode Normalization (NFD)
        _add(cls._unicode_normalize(value, "NFD"))

        # 11. Gzip Decompression
        _add(cls._gzip_decode(value))

        # 12. Zlib Decompression
        _add(cls._zlib_decode(value))

        # 13. Remove Null Bytes
        no_null = value.replace("\x00", "")
        if no_null != value:
            _add(no_null)

        # ─── Mutation Decoders (اختياري) ───

        if include_mutations:
            # 14. ROT13
            _add(cls._rot13_decode(value))

            # 15. Reverse String
            reversed_value = value[::-1]
            _add(reversed_value)

        return results

    # ─── Individual Decoders ───────────────────────────────

    @staticmethod
    def _url_decode(value: str) -> Optional[str]:
        """URL decode."""
        try:
            decoded = urllib.parse.unquote(value)
            return decoded if decoded != value else None
        except Exception:
            return None

    @staticmethod
    def _html_decode(value: str) -> Optional[str]:
        """HTML entities decode."""
        try:
            decoded = html.unescape(value)
            return decoded if decoded != value else None
        except Exception:
            return None

    @staticmethod
    def _unicode_decode(value: str) -> Optional[str]:
        """Unicode escape sequences decode."""
        try:
            if "\\u" in value or "\\x" in value or "\\U" in value:
                decoded = codecs.decode(value, "unicode_escape")
                return decoded if decoded != value else None
            return None
        except Exception:
            return None

    @staticmethod
    def _base64_decode(value: str) -> Optional[str]:
        """Base64 decode."""
        try:
            if not re.match(r"^[A-Za-z0-9+/=]+$", value):
                return None
            if len(value) < 4:
                return None

            padded = value + "=" * (-len(value) % 4)
            decoded_bytes = base64.b64decode(padded, validate=True)
            decoded = decoded_bytes.decode("utf-8", errors="ignore")

            if decoded and decoded.isprintable():
                return decoded
            return None
        except Exception:
            return None

    @staticmethod
    def _hex_decode(value: str) -> Optional[str]:
        """Hex decode."""
        try:
            if value.startswith("0x") or value.startswith("0X"):
                decoded_bytes = bytes.fromhex(value[2:])
                return decoded_bytes.decode("utf-8", errors="ignore")

            if re.match(r"^[0-9a-fA-F]+$", value) and len(value) % 2 == 0:
                if len(value) >= 4:
                    decoded_bytes = bytes.fromhex(value)
                    decoded = decoded_bytes.decode("utf-8", errors="ignore")
                    if decoded and decoded.isprintable():
                        return decoded
            return None
        except Exception:
            return None

    @staticmethod
    def _octal_decode(value: str) -> Optional[str]:
        """Octal decode."""
        try:
            if re.search(r"\\[0-7]{3}", value):
                decoded = re.sub(
                    r"\\([0-7]{3})",
                    lambda m: chr(int(m.group(1), 8)),
                    value,
                )
                return decoded if decoded != value else None
            return None
        except Exception:
            return None

    @staticmethod
    def _quoted_printable_decode(value: str) -> Optional[str]:
        """Quoted-Printable decode."""
        try:
            if re.search(r"=[0-9A-Fa-f]{2}", value):
                decoded_bytes = codecs.decode(value.encode(), "quopri")
                decoded = decoded_bytes.decode("utf-8", errors="ignore")
                return decoded if decoded != value else None
            return None
        except Exception:
            return None

    @staticmethod
    def _rot13_decode(value: str) -> Optional[str]:
        """ROT13 decode."""
        try:
            decoded = codecs.decode(value, "rot13")
            return decoded if decoded != value else None
        except Exception:
            return None

    @staticmethod
    def _unicode_normalize(value: str, form: str) -> Optional[str]:
        """Unicode normalization (NFKC, NFD, NFC, NFKD)."""
        try:
            import unicodedata
            decoded = unicodedata.normalize(form, value)
            return decoded if decoded != value else None
        except Exception:
            return None

    @staticmethod
    def _gzip_decode(value: str) -> Optional[str]:
        """Gzip decompression."""
        try:
            value_bytes = value.encode("latin-1", errors="ignore")
            if value_bytes[:2] == b"\x1f\x8b":
                decoded = gzip.decompress(value_bytes).decode("utf-8", errors="ignore")
                return decoded
            return None
        except Exception:
            return None

    @staticmethod
    def _zlib_decode(value: str) -> Optional[str]:
        """Zlib decompression."""
        try:
            value_bytes = value.encode("latin-1", errors="ignore")
            if value_bytes[:2] in (b"\x78\x9c", b"\x78\x01", b"\x78\xda"):
                decoded = zlib.decompress(value_bytes).decode("utf-8", errors="ignore")
                return decoded
            return None
        except Exception:
            return None

    # ─── Analysis Helpers ──────────────────────────────────

    @classmethod
    def detect_encoding(cls, value: str) -> Dict[str, bool]:
        """بيكشف نوع التشفير المستخدم في الـ payload."""
        return {
            "url_encoded": "%" in value and bool(re.search(r"%[0-9A-Fa-f]{2}", value)),
            "double_url_encoded": bool(re.search(r"%25[0-9A-Fa-f]{2}", value)),
            "html_entities": bool(re.search(r"&#?\w+;", value)),
            "unicode_escape": "\\u" in value or "\\x" in value,
            "base64_like": bool(re.match(r"^[A-Za-z0-9+/=]+$", value)) and len(value) % 4 == 0 and len(value) >= 8,
            "hex_like": bool(re.match(r"^(0x)?[0-9a-fA-F]+$", value)) and len(value) % 2 == 0,
            "octal_like": bool(re.search(r"\\[0-7]{3}", value)),
            "quoted_printable": bool(re.search(r"=[0-9A-Fa-f]{2}", value)),
            "has_null_bytes": "\x00" in value,
            "has_unicode": any(ord(c) > 127 for c in value),
            "has_control_chars": any(ord(c) < 32 and c not in "\t\n\r" for c in value),
            "has_mixed_encoding": cls._has_mixed_encoding(value),
        }

    @staticmethod
    def _has_mixed_encoding(value: str) -> bool:
        """بيفحص لو فيه أكتر من تشفير."""
        indicators = [
            "%" in value,
            "&" in value and ";" in value,
            "\\u" in value,
            "\\x" in value,
        ]
        return sum(indicators) >= 2

    @classmethod
    def get_encoding_summary(cls, value: str) -> str:
        """بترجع ملخص نصي لنوع التشفير."""
        encodings = cls.detect_encoding(value)
        active = [k for k, v in encodings.items() if v]
        return ", ".join(active) if active else "plain"


# ─── Singleton for convenience ─────────────────────────────

payload_decoder = PayloadDecoder()