"""
Encoding Detector — Detects malicious encoding techniques.

بيكشف تقنيات التشفير الخبيثة:
- Homoglyphs (Cyrillic 'а' vs Latin 'a')
- Zero-Width Characters
- Bidi Override
- Null Bytes
- Control Characters
- Entropy Analysis
- Charset Detection
- Unicode Normalization
- Confusable Characters
- Mixed Scripts

ملف مستقل — مش بيعتمد على أي حاجة تانية.
"""

import math
import re
import unicodedata
from collections import Counter
from typing import Dict, List, Optional, Set, Tuple

import structlog

logger = structlog.get_logger()


class EncodingDetector:
    """
    كلاس لكشف تقنيات التشفير الخبيثة.

    بيوفر 10+ طريقة للكشف.
    """

    # ─── Zero-Width Characters ─────────────────────────────
    ZERO_WIDTH_CHARS = {
        "\u200b",  # Zero Width Space
        "\u200c",  # Zero Width Non-Joiner
        "\u200d",  # Zero Width Joiner
        "\u200e",  # Left-to-Right Mark
        "\u200f",  # Right-to-Left Mark
        "\u2060",  # Word Joiner
        "\u2061",  # Function Application
        "\u2062",  # Invisible Times
        "\u2063",  # Invisible Separator
        "\u2064",  # Invisible Plus
        "\ufeff",  # Zero Width No-Break Space (BOM)
    }

    # ─── Bidi Override Characters ──────────────────────────
    BIDI_CHARS = {
        "\u202a",  # Left-to-Right Embedding
        "\u202b",  # Right-to-Left Embedding
        "\u202c",  # Pop Directional Formatting
        "\u202d",  # Left-to-Right Override
        "\u202e",  # Right-to-Left Override
        "\u2066",  # Left-to-Right Isolate
        "\u2067",  # Right-to-Left Isolate
        "\u2068",  # First Strong Isolate
        "\u2069",  # Pop Directional Isolate
    }

    # ─── Homoglyphs Map (Latin → Cyrillic/Greek) ──────────
    HOMOGLYPHS = {
        # Latin → Cyrillic
        "a": "\u0430",  # а (Cyrillic a)
        "c": "\u0441",  # с (Cyrillic c)
        "e": "\u0435",  # е (Cyrillic e)
        "o": "\u043e",  # о (Cyrillic o)
        "p": "\u0440",  # р (Cyrillic p)
        "x": "\u0445",  # х (Cyrillic x)
        "y": "\u0443",  # у (Cyrillic y)
        "i": "\u0456",  # і (Cyrillic i)
        "s": "\u0455",  # ѕ (Cyrillic s)
        "d": "\u0501",  # ԁ (Cyrillic d)
        # Latin → Greek
        "A": "\u0391",  # Α (Greek Alpha)
        "B": "\u0392",  # Β (Greek Beta)
        "E": "\u0395",  # Ε (Greek Epsilon)
        "H": "\u0397",  # Η (Greek Eta)
        "I": "\u0399",  # Ι (Greek Iota)
        "K": "\u039a",  # Κ (Greek Kappa)
        "M": "\u039c",  # Μ (Greek Mu)
        "N": "\u039d",  # Ν (Greek Nu)
        "O": "\u039f",  # Ο (Greek Omicron)
        "P": "\u03a1",  # Ρ (Greek Rho)
        "T": "\u03a4",  # Τ (Greek Tau)
        "X": "\u03a7",  # Χ (Greek Chi)
        "Y": "\u03a5",  # Υ (Greek Upsilon)
        "Z": "\u0396",  # Ζ (Greek Zeta)
    }

    # Reverse lookup
    HOMOGLYPH_REVERSE = {v: k for k, v in HOMOGLYPHS.items()}

    # ─── Scripts Ranges ────────────────────────────────────
    SCRIPT_RANGES = {
        "latin": [
            (0x0041, 0x005A), (0x0061, 0x007A),
            (0x00C0, 0x00FF), (0x0100, 0x017F),
        ],
        "cyrillic": [
            (0x0400, 0x04FF), (0x0500, 0x052F),
        ],
        "greek": [
            (0x0370, 0x03FF), (0x1F00, 0x1FFF),
        ],
        "arabic": [
            (0x0600, 0x06FF), (0x0750, 0x077F),
        ],
        "hebrew": [
            (0x0590, 0x05FF),
        ],
        "cjk": [
            (0x4E00, 0x9FFF), (0x3400, 0x4DBF),
        ],
        "hiragana": [
            (0x3040, 0x309F),
        ],
        "katakana": [
            (0x30A0, 0x30FF),
        ],
        "hangul": [
            (0xAC00, 0xD7AF), (0x1100, 0x11FF),
        ],
    }

    # ─── Main API ──────────────────────────────────────────

    @classmethod
    def detect_all(cls, value: str) -> Dict[str, any]:
        """
        بيكشف كل أنواع التشفير الخبيثة.

        Returns:
            dict فيه كل نوع و لو موجود + score
        """
        if not isinstance(value, str):
            return cls._empty_result()

        return {
            "has_homoglyphs": cls.has_homoglyphs(value),
            "has_zero_width": cls.has_zero_width(value),
            "has_bidi": cls.has_bidi(value),
            "has_null_bytes": cls.has_null_bytes(value),
            "has_control_chars": cls.has_control_chars(value),
            "has_unicode": cls.has_unicode(value),
            "has_mixed_scripts": cls.has_mixed_scripts(value),
            "entropy": cls.calculate_entropy(value),
            "entropy_level": cls.get_entropy_level(value),
            "is_high_entropy": cls.is_high_entropy(value),
            "detected_scripts": cls.detect_scripts(value),
            "normalization_form": cls.detect_normalization_form(value),
            "suspicion_score": cls.get_suspicion_score(value),
            "summary": cls.get_summary(value),
        }

    @classmethod
    def _empty_result(cls) -> Dict[str, any]:
        """نتيجة فاضية لو القيمة مش نص."""
        return {
            "has_homoglyphs": False,
            "has_zero_width": False,
            "has_bidi": False,
            "has_null_bytes": False,
            "has_control_chars": False,
            "has_unicode": False,
            "has_mixed_scripts": False,
            "entropy": 0.0,
            "entropy_level": "none",
            "is_high_entropy": False,
            "detected_scripts": [],
            "normalization_form": "unknown",
            "suspicion_score": 0,
            "summary": "empty",
        }

    # ─── Individual Detectors ──────────────────────────────

    @classmethod
    def has_homoglyphs(cls, value: str) -> bool:
        """
        بيكشف الـ Homoglyphs.

        مثال: 'аdmin' مع 'а' سيريلية بدل Latin 'a'
        """
        if not value:
            return False
        return any(c in cls.HOMOGLYPH_REVERSE for c in value)

    @classmethod
    def has_zero_width(cls, value: str) -> bool:
        """بيكشف الـ Zero-Width Characters."""
        if not value:
            return False
        return any(c in cls.ZERO_WIDTH_CHARS for c in value)

    @classmethod
    def has_bidi(cls, value: str) -> bool:
        """بيكشف الـ Bidi Override."""
        if not value:
            return False
        return any(c in cls.BIDI_CHARS for c in value)

    @staticmethod
    def has_null_bytes(value: str) -> bool:
        """بيكشف الـ Null Bytes."""
        return "\x00" in value if value else False

    @staticmethod
    def has_control_chars(value: str) -> bool:
        """بيكشف الـ Control Characters (غير المسموح)."""
        if not value:
            return False
        # نستثني \t \n \r
        return any(ord(c) < 32 and c not in "\t\n\r" for c in value)

    @staticmethod
    def has_unicode(value: str) -> bool:
        """بيكشف لو فيه Unicode (غير ASCII)."""
        if not value:
            return False
        return any(ord(c) > 127 for c in value)

    @classmethod
    def has_mixed_scripts(cls, value: str) -> bool:
        """
        بيكشف لو فيه أكتر من سكريبت (زي Latin + Cyrillic).
        """
        if not value:
            return False
        scripts = cls.detect_scripts(value)
        # لو فيه أكتر من سكريبت (بعد استثناء common)
        significant = [s for s in scripts if s not in ("common", "unknown")]
        return len(significant) > 1

    # ─── Script Detection ──────────────────────────────────

    @classmethod
    def _char_script(cls, char: str) -> str:
        """بترجع السكريبت بتاع الحرف."""
        code = ord(char)

        # Common / ASCII
        if code < 128:
            if char.isalpha():
                return "latin"
            return "common"

        for script, ranges in cls.SCRIPT_RANGES.items():
            for start, end in ranges:
                if start <= code <= end:
                    return script

        # Unicode categories
        try:
            category = unicodedata.category(char)
            if category.startswith("Z") or category.startswith("P"):
                return "common"
            if category.startswith("N"):
                return "common"
        except Exception:
            pass

        return "unknown"

    @classmethod
    def detect_scripts(cls, value: str) -> List[str]:
        """
        بيكشف كل السكريبتات المستخدمة.
        """
        if not value:
            return []

        scripts: Set[str] = set()
        for char in value:
            if char.isspace():
                continue
            scripts.add(cls._char_script(char))

        return sorted(scripts)

    # ─── Entropy Analysis ──────────────────────────────────

    @staticmethod
    def calculate_entropy(value: str) -> float:
        """
        بيحسب Shannon entropy.

        - نص عادي: entropy منخفض (2-4)
        - نص مشفر: entropy عالي (5-6)
        - Base64: entropy 6
        - Random: entropy 8
        """
        if not value:
            return 0.0

        length = len(value)
        if length == 0:
            return 0.0

        counter = Counter(value)
        entropy = 0.0
        for count in counter.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return round(entropy, 3)

    @staticmethod
    def get_entropy_level(value: str) -> str:
        """بيرجع مستوى الـ entropy."""
        entropy = EncodingDetector.calculate_entropy(value)

        if entropy < 1:
            return "very_low"
        elif entropy < 3:
            return "low"
        elif entropy < 4.5:
            return "medium"
        elif entropy < 5.5:
            return "high"
        else:
            return "very_high"

    @classmethod
    def is_high_entropy(cls, value: str) -> bool:
        """بيفحص لو الـ entropy عالي (مشبوه)."""
        return cls.calculate_entropy(value) > 5.0

    # ─── Unicode Normalization ────────────────────────────

    @staticmethod
    def detect_normalization_form(value: str) -> str:
        """
        بيكشف لو النص محتاج normalization.

        Returns:
            - "nfkc": محتاج NFKC
            - "nfd": محتاج NFD
            - "nfc": محتاج NFC
            - "nfkd": محتاج NFKD
            - "stable": مش محتاج
        """
        if not value:
            return "empty"

        try:
            nfc = unicodedata.normalize("NFC", value)
            nfd = unicodedata.normalize("NFD", value)
            nfkc = unicodedata.normalize("NFKC", value)
            nfkd = unicodedata.normalize("NFKD", value)

            if nfkc != value:
                if nfkc == nfc:
                    return "nfkc"
                elif nfkc == nfd:
                    return "nfkc_from_nfd"
                return "nfkc"
            if nfc != value:
                return "nfc"
            if nfd != value:
                return "nfd"
            if nfkd != value:
                return "nfkd"
            return "stable"
        except Exception:
            return "error"

    @staticmethod
    def normalize(value: str, form: str = "NFKC") -> str:
        """بيوحد النص لـ Unicode form معين."""
        try:
            return unicodedata.normalize(form, value)
        except Exception:
            return value

    @classmethod
    def get_normalized_variants(cls, value: str) -> Dict[str, str]:
        """
        بيرجع كل الـ normalized variants.
        """
        if not value:
            return {}

        variants = {}
        for form in ("NFC", "NFD", "NFKC", "NFKD"):
            try:
                normalized = unicodedata.normalize(form, value)
                if normalized != value:
                    variants[form] = normalized
            except Exception:
                continue
        return variants

    # ─── Homoglyph Removal ─────────────────────────────────

    @classmethod
    def deobfuscate_homoglyphs(cls, value: str) -> str:
        """
        بيحول الـ Homoglyphs لـ Latin.

        مثال: 'аdmin' (Cyrillic a) → 'admin'
        """
        if not value:
            return value

        result = []
        for char in value:
            if char in cls.HOMOGLYPH_REVERSE:
                result.append(cls.HOMOGLYPH_REVERSE[char])
            else:
                result.append(char)

        return "".join(result)

    # ─── Suspicion Score ───────────────────────────────────

    @classmethod
    def get_suspicion_score(cls, value: str) -> int:
        """
        بيحسب درجة الشك (0-100).

        كل نوع له وزن.
        """
        if not value:
            return 0

        score = 0

        # Homoglyphs (خطير جداً - بيلخبط الـ filters)
        if cls.has_homoglyphs(value):
            score += 25

        # Zero-Width (خطير - بيخفي نص)
        if cls.has_zero_width(value):
            score += 20

        # Bidi (خطير - بيعكس النص)
        if cls.has_bidi(value):
            score += 20

        # Null bytes (خطير - بيكسر الـ parsers)
        if cls.has_null_bytes(value):
            score += 15

        # Control chars
        if cls.has_control_chars(value):
            score += 10

        # Mixed scripts (مشبوه)
        if cls.has_mixed_scripts(value):
            score += 15

        # High entropy
        if cls.is_high_entropy(value):
            score += 10

        # Normalization needed
        form = cls.detect_normalization_form(value)
        if form not in ("stable", "empty", "unknown"):
            score += 5

        return min(score, 100)

    # ─── Summary ───────────────────────────────────────────

    @classmethod
    def get_summary(cls, value: str) -> str:
        """بيرجع ملخص نصي."""
        if not value:
            return "empty"

        findings = []

        if cls.has_homoglyphs(value):
            findings.append("homoglyphs")
        if cls.has_zero_width(value):
            findings.append("zero-width")
        if cls.has_bidi(value):
            findings.append("bidi")
        if cls.has_null_bytes(value):
            findings.append("null-bytes")
        if cls.has_control_chars(value):
            findings.append("control-chars")
        if cls.has_mixed_scripts(value):
            findings.append("mixed-scripts")

        if not findings:
            return "clean"

        return ", ".join(findings)

    # ─── Advanced Detection ────────────────────────────────

    @classmethod
    def is_suspicious(cls, value: str, threshold: int = 30) -> bool:
        """
        بيفحص لو النص مشبوه.

        Args:
            value: النص
            threshold: حد الشك (default: 30)
        """
        return cls.get_suspicion_score(value) >= threshold

    @classmethod
    def sanitize(cls, value: str) -> str:
        """
        بينضف النص من التشفير الخبيث.

        - يشيل Zero-Width
        - يشيل Bidi
        - يشيل Null bytes
        - يحول Homoglyphs
        - يوحد Unicode
        """
        if not value:
            return value

        # 1. شيل Zero-Width
        result = "".join(c for c in value if c not in cls.ZERO_WIDTH_CHARS)

        # 2. شيل Bidi
        result = "".join(c for c in result if c not in cls.BIDI_CHARS)

        # 3. شيل Null bytes
        result = result.replace("\x00", "")

        # 4. حوّل Homoglyphs
        result = cls.deobfuscate_homoglyphs(result)

        # 5. وحد Unicode
        result = cls.normalize(result, "NFKC")

        return result


# ─── Singleton ─────────────────────────────────────────────

encoding_detector = EncodingDetector()