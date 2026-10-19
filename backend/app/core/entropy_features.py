"""
Entropy Features — Information-theoretic feature extraction.

بيوفر:
- Shannon entropy (character-level)
- Shannon entropy (byte-level)
- Shannon entropy (word-level)
- Renyi entropy (order 2)
- Min entropy
- Compression ratio (proxy for entropy)
- Randomness score
- Unique character ratio
- Chi-square test (uniformity)
- Kolmogorov complexity estimate
- Base64/encoded content detection

الفكرة:
- النصوص المشفرة/العشوائية عندها entropy عالي
- الـ payloads الخبيثة غالباً encoded/obfuscated
- الـ bots بتبعت requests بانتظام (entropy منخفض)

الاستخدام:
- ml_payload_detector.py
- anomaly_detection.py
- input_validator.py
- heuristic_scorer.py
- feature_extractor.py
"""

import math
import re
import zlib
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import structlog

logger = structlog.get_logger()


class EntropyFeatures:
    """
    Entropy & Randomness Features.

    بيستخرج features مبنية على نظرية المعلومات.
    """

    # ─── Config ────────────────────────────────────────────
    MIN_TEXT_LENGTH = 4
    MIN_LENGTH_FOR_COMPRESSION_CHECK = 100

    # ─── Charset Patterns ─────────────────────────────────
    BASE64_CHARSET = re.compile(r"^[A-Za-z0-9+/=\s]+$")
    BASE64_URL_CHARSET = re.compile(r"^[A-Za-z0-9_\-=\s]+$")
    HEX_CHARSET = re.compile(r"^[0-9a-fA-F\s]+$")

    # ─── Feature Names ────────────────────────────────────
    FEATURE_NAMES = [
        "shannon_char_entropy",
        "shannon_byte_entropy",
        "shannon_word_entropy",
        "renyi_entropy_2",
        "min_entropy",
        "max_entropy",
        "normalized_entropy",
        "compression_ratio",
        "randomness_score",
        "unique_char_ratio",
        "unique_byte_ratio",
        "chi_square_score",
        "text_length",
        "entropy_per_char",
    ]

    # ═══════════════════════════════════════════════════════
    #  Shannon Entropy
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def shannon_entropy(
        data: str,
        base: int = 2,
    ) -> float:
        """
        بيحسب Shannon entropy.

        Args:
            data: النص
            base: أساس اللوغاريتم (2 للـ bits, e للـ nats)

        Returns:
            entropy value
        """
        if not data:
            return 0.0

        try:
            counter = Counter(data)
            length = len(data)

            entropy = 0.0
            for count in counter.values():
                p = count / length
                if p > 0:
                    entropy -= p * math.log(p, base)

            return float(entropy)
        except (ValueError, ZeroDivisionError):
            return 0.0

    @staticmethod
    def shannon_byte_entropy(data: str) -> float:
        """Shannon entropy على مستوى البايتات."""
        if not data:
            return 0.0

        try:
            byte_data = data.encode("utf-8", errors="replace")
            counter = Counter(byte_data)
            length = len(byte_data)

            entropy = 0.0
            for count in counter.values():
                p = count / length
                if p > 0:
                    entropy -= p * math.log2(p)

            return float(entropy)
        except (ValueError, ZeroDivisionError):
            return 0.0

    @staticmethod
    def shannon_word_entropy(data: str) -> float:
        """Shannon entropy على مستوى الكلمات."""
        if not data:
            return 0.0

        try:
            words = re.findall(r"\w+", data.lower())
            if not words:
                return 0.0

            counter = Counter(words)
            length = len(words)

            entropy = 0.0
            for count in counter.values():
                p = count / length
                if p > 0:
                    entropy -= p * math.log2(p)

            return float(entropy)
        except (ValueError, ZeroDivisionError):
            return 0.0

    # ═══════════════════════════════════════════════════════
    #  Renyi Entropy
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def renyi_entropy(
        data: str,
        alpha: float = 2.0,
    ) -> float:
        """بيحسب Renyi entropy (order alpha)."""
        if not data or alpha <= 0 or alpha == 1:
            return 0.0

        try:
            counter = Counter(data)
            length = len(data)

            sum_p_alpha = sum(
                (count / length) ** alpha
                for count in counter.values()
            )

            if sum_p_alpha <= 0:
                return 0.0

            entropy = (1.0 / (1.0 - alpha)) * math.log2(sum_p_alpha)
            return float(max(0.0, entropy))
        except (ValueError, ZeroDivisionError, OverflowError):
            return 0.0

    # ═══════════════════════════════════════════════════════
    #  Min Entropy
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def min_entropy(data: str) -> float:
        """Min entropy = -log2(max probability)."""
        if not data:
            return 0.0

        try:
            counter = Counter(data)
            length = len(data)

            max_p = max(count / length for count in counter.values())

            if max_p <= 0:
                return 0.0

            return float(-math.log2(max_p))
        except (ValueError, ZeroDivisionError):
            return 0.0

    # ═══════════════════════════════════════════════════════
    #  Max Entropy
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def max_entropy(data: str) -> float:
        """Max entropy ممكنة."""
        if not data:
            return 0.0

        try:
            unique_chars = len(set(data))
            if unique_chars <= 1:
                return 0.0
            return float(math.log2(unique_chars))
        except (ValueError, ZeroDivisionError):
            return 0.0

    # ═══════════════════════════════════════════════════════
    #  Normalized Entropy
    # ═══════════════════════════════════════════════════════

    @classmethod
    def normalized_entropy(cls, data: str) -> float:
        """Shannon entropy مُطبَّعة (0.0 - 1.0)."""
        if not data or len(data) < 2:
            return 0.0

        shannon = cls.shannon_entropy(data, base=2)
        max_ent = cls.max_entropy(data)

        if max_ent <= 0:
            return 0.0

        return float(min(shannon / max_ent, 1.0))

    # ═══════════════════════════════════════════════════════
    #  Compression Ratio
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def compression_ratio(data: str) -> float:
        """نسبة الضغط (مؤشر على entropy)."""
        if not data:
            return 1.0

        try:
            raw_bytes = data.encode("utf-8", errors="replace")

            if len(raw_bytes) == 0:
                return 1.0

            compressed = zlib.compress(raw_bytes, level=6)
            ratio = len(compressed) / len(raw_bytes)

            return float(min(max(ratio, 0.0), 1.0))
        except (zlib.error, ValueError):
            return 1.0

    # ═══════════════════════════════════════════════════════
    #  Randomness Score
    # ═══════════════════════════════════════════════════════

    @classmethod
    def randomness_score(cls, data: str) -> float:
        """بيعمل score للعشوائية (0-1)."""
        if not data or len(data) < cls.MIN_TEXT_LENGTH:
            return 0.0

        try:
            norm_entropy = cls.normalized_entropy(data)
            comp_ratio = cls.compression_ratio(data)
            unique_ratio = len(set(data)) / len(data)

            score = (
                norm_entropy * 0.5
                + (1.0 - comp_ratio) * 0.3
                + unique_ratio * 0.2
            )

            return float(min(max(score, 0.0), 1.0))
        except (ValueError, ZeroDivisionError):
            return 0.0

    # ═══════════════════════════════════════════════════════
    #  Unique Ratios
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def unique_char_ratio(data: str) -> float:
        """نسبة الحروف الفريدة."""
        if not data:
            return 0.0
        return float(len(set(data)) / len(data))

    @staticmethod
    def unique_byte_ratio(data: str) -> float:
        """نسبة البايتات الفريدة."""
        if not data:
            return 0.0
        try:
            byte_data = data.encode("utf-8", errors="replace")
            if not byte_data:
                return 0.0
            return float(len(set(byte_data)) / len(byte_data))
        except (ValueError, AttributeError):
            return 0.0

    # ═══════════════════════════════════════════════════════
    #  Chi-Square Test
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def chi_square_score(data: str) -> float:
        """Chi-square test للـ uniformity."""
        if not data or len(data) < 4:
            return 0.0

        try:
            counter = Counter(data)
            length = len(data)
            expected = length / len(counter)

            chi_sq = sum(
                ((count - expected) ** 2) / expected
                for count in counter.values()
            )

            df = max(len(counter) - 1, 1)
            normalized = chi_sq / df

            return float(normalized)
        except (ValueError, ZeroDivisionError):
            return 0.0

    # ═══════════════════════════════════════════════════════
    #  Main: Extract All Features
    # ═══════════════════════════════════════════════════════

    @classmethod
    def extract(cls, data: str) -> Dict[str, float]:
        """بيستخرج كل الـ entropy features."""
        features: Dict[str, float] = {}

        if not data:
            for name in cls.FEATURE_NAMES:
                features[name] = 0.0
            return features

        shannon_char = cls.shannon_entropy(data, base=2)
        shannon_byte = cls.shannon_byte_entropy(data)
        shannon_word = cls.shannon_word_entropy(data)
        renyi_2 = cls.renyi_entropy(data, alpha=2.0)
        min_ent = cls.min_entropy(data)
        max_ent = cls.max_entropy(data)
        norm_ent = cls.normalized_entropy(data)
        comp_ratio = cls.compression_ratio(data)
        random_score = cls.randomness_score(data)
        uniq_char = cls.unique_char_ratio(data)
        uniq_byte = cls.unique_byte_ratio(data)
        chi_sq = cls.chi_square_score(data)

        length = float(len(data))
        entropy_per_char = shannon_char / length if length > 0 else 0.0

        features.update({
            "shannon_char_entropy": float(shannon_char),
            "shannon_byte_entropy": float(shannon_byte),
            "shannon_word_entropy": float(shannon_word),
            "renyi_entropy_2": float(renyi_2),
            "min_entropy": float(min_ent),
            "max_entropy": float(max_ent),
            "normalized_entropy": float(norm_ent),
            "compression_ratio": float(comp_ratio),
            "randomness_score": float(random_score),
            "unique_char_ratio": float(uniq_char),
            "unique_byte_ratio": float(uniq_byte),
            "chi_square_score": float(chi_sq),
            "text_length": length,
            "entropy_per_char": float(entropy_per_char),
        })

        return features

    @classmethod
    def extract_as_vector(cls, data: str) -> np.ndarray:
        """بيستخرج الـ features كـ numpy vector."""
        features = cls.extract(data)
        return np.array(
            [features[name] for name in cls.FEATURE_NAMES],
            dtype=np.float32,
        )

    @classmethod
    def get_feature_names(cls) -> List[str]:
        """بيرجع أسماء الـ features."""
        return list(cls.FEATURE_NAMES)

    # ═══════════════════════════════════════════════════════
    #  Charset Detection
    # ═══════════════════════════════════════════════════════

    @classmethod
    def _charset_match(cls, data: str) -> List[str]:
        """
        بيكشف لو النص كله من charset معين.

        Returns:
            قائمة بأسماء الـ charsets المطابقة
        """
        matches = []
        stripped = data.strip()

        if len(stripped) < 8:
            return matches

        # شيل المسافات للاختبار
        no_space = (
            stripped
            .replace(" ", "")
            .replace("\n", "")
            .replace("\t", "")
        )

        if not no_space:
            return matches

        # اختبار base64
        if cls.BASE64_CHARSET.match(stripped):
            # لو كل الـ chars في base64
            # بس مش hex (hex ممكن يكون substring من base64)
            is_hex = cls.HEX_CHARSET.match(no_space) is not None
            if not is_hex or len(no_space) < 16:
                matches.append("base64_charset")

        # اختبار hex (لازم عدد زوجي)
        if cls.HEX_CHARSET.match(no_space) and len(no_space) >= 16:
            if len(no_space) % 2 == 0:
                matches.append("hex_charset")

        return matches

    # ═══════════════════════════════════════════════════════
    #  High-Level Helpers
    # ═══════════════════════════════════════════════════════

    @classmethod
    def is_likely_encoded(cls, data: str) -> Dict[str, Any]:
        """
        بيحدد لو النص encoded/obfuscated.

        Returns:
            dict فيه: is_encoded, confidence, reasons
        """
        if not data or len(data) < cls.MIN_TEXT_LENGTH:
            return {
                "is_encoded": False,
                "confidence": 0.0,
                "reasons": [],
                "charset_matches": [],
            }

        features = cls.extract(data)
        reasons = []
        score = 0.0

        # 1. entropy عالي جداً
        if features["normalized_entropy"] > 0.85:
            reasons.append("very_high_entropy")
            score += 30
        elif features["normalized_entropy"] > 0.7:
            reasons.append("high_entropy")
            score += 15

        # 2. compression ratio منخفض (repeated content)
        if features["compression_ratio"] < 0.4:
            reasons.append("low_compression_ratio")
            score += 25
        # 2b. compression ratio عالي جداً + entropy عالي = encoded
        # بس نتأكد إن النص طويل كفاية (عشان zlib overhead على النصوص القصيرة)
        elif (
            len(data) >= cls.MIN_LENGTH_FOR_COMPRESSION_CHECK
            and features["compression_ratio"] > 0.85
            and features["normalized_entropy"] > 0.8
        ):
            reasons.append("incompressible_high_entropy")
            score += 30

        # 3. randomness score عالي
        if features["randomness_score"] > 0.7:
            reasons.append("high_randomness")
            score += 25
        elif features["randomness_score"] > 0.55:
            reasons.append("moderate_randomness")
            score += 10

        # 4. unique char ratio
        if features["unique_char_ratio"] > 0.7:
            reasons.append("many_unique_chars")
            score += 15
        elif features["unique_char_ratio"] > 0.5:
            score += 5

        # 5. Charset detection (الأقوى)
        charset_matches = cls._charset_match(data)
        if "base64_charset" in charset_matches:
            reasons.append("base64_charset")
            score += 35
        if "hex_charset" in charset_matches:
            reasons.append("hex_charset")
            score += 30

        confidence = min(score, 100)

        return {
            "is_encoded": confidence >= 50,
            "confidence": confidence,
            "reasons": reasons,
            "charset_matches": charset_matches,
            "features": features,
        }

    @classmethod
    def compare_entropy(
        cls,
        data1: str,
        data2: str,
    ) -> Dict[str, Any]:
        """بيقارن entropy نصين."""
        f1 = cls.extract(data1)
        f2 = cls.extract(data2)

        return {
            "shannon_diff": f1["shannon_char_entropy"] - f2["shannon_char_entropy"],
            "randomness_diff": f1["randomness_score"] - f2["randomness_score"],
            "data1_features": f1,
            "data2_features": f2,
        }


# ─── Standalone functions ─────────────────────────────

def shannon_entropy(data: str, base: int = 2) -> float:
    """Shortcut for EntropyFeatures.shannon_entropy."""
    return EntropyFeatures.shannon_entropy(data, base)


def normalized_entropy(data: str) -> float:
    """Shortcut for EntropyFeatures.normalized_entropy."""
    return EntropyFeatures.normalized_entropy(data)


def randomness_score(data: str) -> float:
    """Shortcut for EntropyFeatures.randomness_score."""
    return EntropyFeatures.randomness_score(data)


def compression_ratio(data: str) -> float:
    """Shortcut for EntropyFeatures.compression_ratio."""
    return EntropyFeatures.compression_ratio(data)


def extract_entropy_features(data: str) -> Dict[str, float]:
    """Shortcut for EntropyFeatures.extract."""
    return EntropyFeatures.extract(data)


def is_likely_encoded(data: str) -> Dict[str, Any]:
    """Shortcut for EntropyFeatures.is_likely_encoded."""
    return EntropyFeatures.is_likely_encoded(data)