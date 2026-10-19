"""
Unicode Normalizer — Normalizes and canonicalizes Unicode strings.

بيوفر:
- Normalize: توحيد Unicode (NFC, NFD, NFKC, NFKD)
- Case Folding: توحيد حالة الأحرف
- Remove Diacritics: شيل التشكيل (é → e)
- ASCII Conversion: تحويل لـ ASCII
- Confusable Mapping: توحيد الحروف المتشابهة
- Fuzzy Compare: مقارنة تقريبية (Levenshtein)
- Homoglyph Attack Detection: كشف هجمات Homoglyph
- Canonical Form: الشكل القياسي
- Unicode Categories: تصنيف الحروف
- Strip Invisible: شيل الحروف المخفية

ملف مستقل — مش بيعتمد على أي حاجة تانية.
"""

import re
import unicodedata
from typing import Dict, List, Optional, Set, Tuple

import structlog

logger = structlog.get_logger()


class UnicodeNormalizer:
    """
    كلاس لتوحيد النصوص و canonicalization.

    بيوفر 10+ وظيفة.
    """

    # ─── Invisible Characters ──────────────────────────────
    INVISIBLE_CHARS = {
        "\u200b",  # Zero Width Space
        "\u200c",  # Zero Width Non-Joiner
        "\u200d",  # Zero Width Joiner
        "\u200e",  # Left-to-Right Mark
        "\u200f",  # Right-to-Left Mark
        "\u202a",  # Left-to-Right Embedding
        "\u202b",  # Right-to-Left Embedding
        "\u202c",  # Pop Directional Formatting
        "\u202d",  # Left-to-Right Override
        "\u202e",  # Right-to-Left Override
        "\u2060",  # Word Joiner
        "\u2061",  # Function Application
        "\u2062",  # Invisible Times
        "\u2063",  # Invisible Separator
        "\u2064",  # Invisible Plus
        "\u2066",  # Left-to-Right Isolate
        "\u2067",  # Right-to-Left Isolate
        "\u2068",  # First Strong Isolate
        "\u2069",  # Pop Directional Isolate
        "\ufeff",  # Zero Width No-Break Space
        "\u00ad",  # Soft Hyphen
        "\u034f",  # Combining Grapheme Joiner
        "\u180e",  # Mongolian Vowel Separator
    }

    # ─── Confusables Map ───────────────────────────────────
    CONFUSABLES = {
        # Cyrillic → Latin
        "\u0430": "a",  # а → a
        "\u0435": "e",  # е → e
        "\u043e": "o",  # о → o
        "\u0440": "p",  # р → p
        "\u0441": "c",  # с → c
        "\u0445": "x",  # х → x
        "\u0443": "y",  # у → y
        "\u0456": "i",  # і → i
        "\u0455": "s",  # ѕ → s
        "\u0501": "d",  # ԁ → d
        "\u04bb": "h",  # һ → h
        "\u0458": "j",  # ј → j
        "\u04cf": "l",  # ӏ → l
        "\u043c": "m",  # м → m
        "\u0442": "t",  # т → t
        "\u0475": "v",  # ѵ → v
        "\u051b": "w",  # ԛ → w
        "\u0437": "3",  # з → 3 (نادر)
        # Greek → Latin
        "\u0391": "A",  # Α → A
        "\u0392": "B",  # Β → B
        "\u0395": "E",  # Ε → E
        "\u0396": "Z",  # Ζ → Z
        "\u0397": "H",  # Η → H
        "\u0399": "I",  # Ι → I
        "\u039a": "K",  # Κ → K
        "\u039c": "M",  # Μ → M
        "\u039d": "N",  # Ν → N
        "\u039f": "O",  # Ο → O
        "\u03a1": "P",  # Ρ → P
        "\u03a4": "T",  # Τ → T
        "\u03a5": "Y",  # Υ → Y
        "\u03a7": "X",  # Χ → X
        # Arabic-Indic digits
        "\u0660": "0",  # ٠ → 0
        "\u0661": "1",  # ١ → 1
        "\u0662": "2",  # ٢ → 2
        "\u0663": "3",  # ٣ → 3
        "\u0664": "4",  # ٤ → 4
        "\u0665": "5",  # ٥ → 5
        "\u0666": "6",  # ٦ → 6
        "\u0667": "7",  # ٧ → 7
        "\u0668": "8",  # ٨ → 8
        "\u0669": "9",  # ٩ → 9
        # Full-width → Half-width
        "\uff41": "a", "\uff42": "b", "\uff43": "c", "\uff44": "d",
        "\uff45": "e", "\uff46": "f", "\uff47": "g", "\uff48": "h",
        "\uff49": "i", "\uff4a": "j", "\uff4b": "k", "\uff4c": "l",
        "\uff4d": "m", "\uff4e": "n", "\uff4f": "o", "\uff50": "p",
        "\uff51": "q", "\uff52": "r", "\uff53": "s", "\uff54": "t",
        "\uff55": "u", "\uff56": "v", "\uff57": "w", "\uff58": "x",
        "\uff59": "y", "\uff5a": "z",
        "\uff21": "A", "\uff22": "B", "\uff23": "C", "\uff24": "D",
        "\uff25": "E", "\uff26": "F", "\uff27": "G", "\uff28": "H",
        "\uff29": "I", "\uff2a": "J", "\uff2b": "K", "\uff2c": "L",
        "\uff2d": "M", "\uff2e": "N", "\uff2f": "O", "\uff30": "P",
        "\uff31": "Q", "\uff32": "R", "\uff33": "S", "\uff34": "T",
        "\uff35": "U", "\uff36": "V", "\uff37": "W", "\uff38": "X",
        "\uff39": "Y", "\uff3a": "Z",
        "\uff10": "0", "\uff11": "1", "\uff12": "2", "\uff13": "3",
        "\uff14": "4", "\uff15": "5", "\uff16": "6", "\uff17": "7",
        "\uff18": "8", "\uff19": "9",
    }

    # ─── Main API ──────────────────────────────────────────

    @classmethod
    def canonicalize(cls, value: str) -> str:
        """
        بيرجع الشكل القياسي للنص.

        ده بيطبق كل حاجة:
        1. NFKC normalization
        2. Case folding (lowercase)
        3. Remove invisible chars
        4. Remove diacritics
        5. Map confusables
        6. Convert to ASCII
        """
        if not value:
            return value

        result = value

        # 1. NFKC
        result = cls.normalize(result, "NFKC")

        # 2. Case folding
        result = result.casefold()

        # 3. Remove invisible
        result = cls.strip_invisible(result)

        # 4. Remove diacritics
        result = cls.remove_diacritics(result)

        # 5. Map confusables
        result = cls.deconfuse(result)

        # 6. Convert to ASCII
        result = cls.to_ascii(result)

        return result

    # ─── Normalization ─────────────────────────────────────

    @staticmethod
    def normalize(value: str, form: str = "NFKC") -> str:
        """
        بيوحد النص لـ Unicode form.

        Args:
            value: النص
            form: NFC / NFD / NFKC / NFKD

        Returns:
            النص الموحد
        """
        if not value:
            return value
        try:
            return unicodedata.normalize(form, value)
        except Exception as e:
            logger.warning("normalization_failed", form=form, error=str(e))
            return value

    @classmethod
    def get_all_forms(cls, value: str) -> Dict[str, str]:
        """
        بيرجع كل الـ Unicode forms.

        Returns:
            dict فيه كل form والقيمة بتاعته
        """
        if not value:
            return {}
        return {
            "original": value,
            "nfc": cls.normalize(value, "NFC"),
            "nfd": cls.normalize(value, "NFD"),
            "nfkc": cls.normalize(value, "NFKC"),
            "nfkd": cls.normalize(value, "NFKD"),
        }

    # ─── Case Folding ──────────────────────────────────────

    @staticmethod
    def case_fold(value: str) -> str:
        """توحيد حالة الأحرف (أقوى من lower())."""
        if not value:
            return value
        return value.casefold()

    # ─── Diacritics ────────────────────────────────────────

    @staticmethod
    def remove_diacritics(value: str) -> str:
        """
        بيشيل التشكيل.

        مثال: café → cafe
        """
        if not value:
            return value

        # NFD يفصل الحرف عن التشكيل
        normalized = unicodedata.normalize("NFD", value)

        # شيل Combining Diacritical Marks
        result = "".join(
            c for c in normalized
            if not unicodedata.combining(c)
        )

        # رجع لـ NFC
        return unicodedata.normalize("NFC", result)

    # ─── Invisible Characters ──────────────────────────────

    @classmethod
    def strip_invisible(cls, value: str) -> str:
        """بيشيل الحروف المخفية (Zero-Width, Bidi, إلخ)."""
        if not value:
            return value
        return "".join(c for c in value if c not in cls.INVISIBLE_CHARS)

    @classmethod
    def has_invisible(cls, value: str) -> bool:
        """بيفحص لو فيه حروف مخفية."""
        if not value:
            return False
        return any(c in cls.INVISIBLE_CHARS for c in value)

    @classmethod
    def get_invisible_chars(cls, value: str) -> List[str]:
        """بيرجع كل الحروف المخفية."""
        if not value:
            return []
        return [c for c in value if c in cls.INVISIBLE_CHARS]

    # ─── Confusables ───────────────────────────────────────

    @classmethod
    def deconfuse(cls, value: str) -> str:
        """
        بيحول الحروف المتشابهة لـ Latin.

        مثال: 'аdmin' (Cyrillic a) → 'admin'
        """
        if not value:
            return value

        return "".join(
            cls.CONFUSABLES.get(c, c)
            for c in value
        )

    @classmethod
    def has_confusables(cls, value: str) -> bool:
        """بيفحص لو فيه حروف متشابهة."""
        if not value:
            return False
        return any(c in cls.CONFUSABLES for c in value)

    @classmethod
    def get_confusables(cls, value: str) -> Dict[str, str]:
        """بيرجع كل الحروف المتشابهة والبدائل."""
        if not value:
            return {}
        return {
            c: cls.CONFUSABLES[c]
            for c in value
            if c in cls.CONFUSABLES
        }

    # ─── ASCII Conversion ──────────────────────────────────

    @staticmethod
    def to_ascii(value: str, errors: str = "ignore") -> str:
        """
        بيحول النص لـ ASCII.

        Args:
            value: النص
            errors: ignore / replace / strict
        """
        if not value:
            return value
        try:
            return value.encode("ascii", errors=errors).decode("ascii")
        except Exception:
            return value

    @staticmethod
    def is_ascii(value: str) -> bool:
        """بيفحص لو النص كله ASCII."""
        if not value:
            return True
        try:
            value.encode("ascii")
            return True
        except UnicodeEncodeError:
            return False

    # ─── Fuzzy Comparison ──────────────────────────────────

    @staticmethod
    def levenshtein_distance(s1: str, s2: str) -> int:
        """
        بيحسب Levenshtein distance (عدد التعديلات).

        ده أساس fuzzy matching.
        """
        if not s1:
            return len(s2)
        if not s2:
            return len(s1)

        # Dynamic programming
        m, n = len(s1), len(s2)
        dp = [[0] * (n + 1) for _ in range(m + 1)]

        for i in range(m + 1):
            dp[i][0] = i
        for j in range(n + 1):
            dp[0][j] = j

        for i in range(1, m + 1):
            for j in range(1, n + 1):
                if s1[i - 1] == s2[j - 1]:
                    dp[i][j] = dp[i - 1][j - 1]
                else:
                    dp[i][j] = 1 + min(
                        dp[i - 1][j],      # delete
                        dp[i][j - 1],      # insert
                        dp[i - 1][j - 1],  # replace
                    )

        return dp[m][n]

    @classmethod
    def similarity(cls, s1: str, s2: str) -> float:
        """
        بيحسب نسبة التشابه (0-1).

        1.0 = متطابق
        0.0 = مختلف تماماً
        """
        if not s1 and not s2:
            return 1.0
        if not s1 or not s2:
            return 0.0

        # canonicalize الأول
        c1 = cls.canonicalize(s1)
        c2 = cls.canonicalize(s2)

        if c1 == c2:
            return 1.0

        max_len = max(len(c1), len(c2))
        if max_len == 0:
            return 1.0

        distance = cls.levenshtein_distance(c1, c2)
        return 1.0 - (distance / max_len)

    @classmethod
    def are_similar(
        cls,
        s1: str,
        s2: str,
        threshold: float = 0.9,
    ) -> bool:
        """
        بيفحص لو النصين متشابهين.

        Args:
            s1, s2: النصين
            threshold: حد التشابه (default: 0.9)
        """
        return cls.similarity(s1, s2) >= threshold

    # ─── Homoglyph Attack Detection ────────────────────────

    @classmethod
    def is_homoglyph_attack(
        cls,
        value: str,
        target: str,
    ) -> bool:
        """
        بيفحص لو ده هجوم Homoglyph.

        يعني: النص شبه الـ target بس مش هو.
        """
        # لو النص = الـ target بالظبط → مش هجوم
        if value == target:
            return False

        # لو الـ canonicalized = الـ target → هجوم!
        canonical = cls.canonicalize(value)
        target_canonical = cls.canonicalize(target)

        return canonical == target_canonical

    # ─── Unicode Categories ────────────────────────────────

    @staticmethod
    def get_category(char: str) -> str:
        """بيرجع Unicode category للحرف."""
        try:
            return unicodedata.category(char)
        except Exception:
            return "Cn"

    @classmethod
    def get_categories(cls, value: str) -> Dict[str, int]:
        """بيرجع عدد الحروف في كل category."""
        if not value:
            return {}

        counter: Dict[str, int] = {}
        for char in value:
            cat = cls.get_category(char)
            counter[cat] = counter.get(cat, 0) + 1
        return counter

    # ─── Batch Operations ──────────────────────────────────

    @classmethod
    def canonicalize_dict(cls, data: Dict) -> Dict:
        """canonicalize كل القيم في dict."""
        if not isinstance(data, dict):
            return data

        return {
            k: cls.canonicalize(v) if isinstance(v, str) else v
            for k, v in data.items()
        }

    @classmethod
    def canonicalize_list(cls, data: List) -> List:
        """canonicalize كل القيم في list."""
        if not isinstance(data, list):
            return data

        return [
            cls.canonicalize(item) if isinstance(item, str) else item
            for item in data
        ]

    # ─── Summary ───────────────────────────────────────────

    @classmethod
    def get_summary(cls, value: str) -> Dict[str, any]:
        """بيرجع ملخص كامل."""
        if not value:
            return {
                "length": 0,
                "is_ascii": True,
                "has_invisible": False,
                "has_confusables": False,
                "category": "empty",
            }

        return {
            "length": len(value),
            "is_ascii": cls.is_ascii(value),
            "has_invisible": cls.has_invisible(value),
            "has_confusables": cls.has_confusables(value),
            "canonical": cls.canonicalize(value),
            "invisible_count": len(cls.get_invisible_chars(value)),
            "confusables_count": len(cls.get_confusables(value)),
        }


# ─── Singleton ─────────────────────────────────────────────

unicode_normalizer = UnicodeNormalizer()