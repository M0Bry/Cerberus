"""
Sequence Features — Sequential pattern feature extraction.

بيوفر:
- N-gram extraction & counting
- Sequence entropy
- Repetition patterns detection
- Markov chain transitions
- Sequential ID patterns (1, 2, 3...)
- Common prefix/suffix analysis
- Edit distance features
- Pattern-based features (URL, email, paths)
- Periodic pattern detection
- Sequence compression ratio

الفكرة:
- بيستخرج features من sequences (lists of tokens/strings/IDs)
- بيكشف الأنماط المتكررة والسلوك الآلي
- بيساعد في كشف:
  * Sequential ID scanning
  * Parameter fuzzing
  * Automated scraping

الاستخدام:
- pattern_detector.py
- request_analytics.py
- scraping_detector.py
- feature_extractor.py
- session_analyzer.py
"""

import math
import re
from collections import Counter
from typing import Any, Dict, List, Optional, Set, Tuple

import numpy as np
import structlog

logger = structlog.get_logger()


class SequenceFeatures:
    """
    Sequence Feature Extraction.

    بيستخرج features من sequences.
    """

    # ─── Config ────────────────────────────────────────────
    MIN_SEQUENCE_LENGTH = 3
    DEFAULT_NGRAM_SIZES = [2, 3, 4]

    # ─── Feature Names ────────────────────────────────────
    FEATURE_NAMES = [
        "length",
        "unique_ratio",
        "avg_ngram_count",
        "max_ngram_count",
        "ngram_entropy",
        "repetition_score",
        "sequential_id_score",
        "markov_entropy",
        "periodic_score",
        "compression_ratio",
        "common_prefix_length",
        "avg_common_prefix_ratio",
        "transition_uniformity",
    ]

    # ═══════════════════════════════════════════════════════
    #  N-gram Extraction
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def extract_ngrams(
        sequence: List[Any],
        n: int = 2,
    ) -> List[Tuple]:
        """
        بيستخرج n-grams من sequence.

        Args:
            sequence: قائمة عناصر
            n: حجم الـ n-gram

        Returns:
            قائمة tuples
        """
        if not sequence or n <= 0 or len(sequence) < n:
            return []

        try:
            return [
                tuple(sequence[i:i + n])
                for i in range(len(sequence) - n + 1)
            ]
        except (TypeError, ValueError):
            return []

    @staticmethod
    def ngram_frequencies(
        sequence: List[Any],
        n: int = 2,
    ) -> Counter:
        """بيرجع تكرار كل n-gram."""
        ngrams = SequenceFeatures.extract_ngrams(sequence, n)
        return Counter(ngrams)

    # ═══════════════════════════════════════════════════════
    #  Unique Ratio
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def unique_ratio(sequence: List[Any]) -> float:
        """نسبة العناصر الفريدة."""
        if not sequence:
            return 0.0
        try:
            unique = len(set(sequence))
            return float(unique / len(sequence))
        except TypeError:
            # غير قابل للـ hash → استخدم string representation
            unique = len({str(x) for x in sequence})
            return float(unique / len(sequence))

    # ═══════════════════════════════════════════════════════
    #  N-gram Statistics
    # ═══════════════════════════════════════════════════════

    @classmethod
    def ngram_stats(
        cls,
        sequence: List[Any],
        n: int = 2,
    ) -> Dict[str, float]:
        """
        إحصائيات الـ n-grams.

        Returns:
            dict فيه: count, unique, entropy, max_freq
        """
        if not sequence or len(sequence) < n:
            return {
                "count": 0.0,
                "unique": 0.0,
                "entropy": 0.0,
                "max_freq": 0.0,
            }

        freqs = cls.ngram_frequencies(sequence, n)
        total = sum(freqs.values())

        if total == 0:
            return {
                "count": 0.0,
                "unique": 0.0,
                "entropy": 0.0,
                "max_freq": 0.0,
            }

        # احسب entropy للـ n-grams
        entropy = 0.0
        for count in freqs.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)

        return {
            "count": float(total),
            "unique": float(len(freqs)),
            "entropy": float(entropy),
            "max_freq": float(max(freqs.values())),
        }

    # ═══════════════════════════════════════════════════════
    #  Repetition Detection
    # ═══════════════════════════════════════════════════════

    @classmethod
    def repetition_score(cls, sequence: List[Any]) -> float:
        """
        بيعمل score للتكرار (0-1).

        score عالي = تكرار كتير (bot-like)
        score منخفض = تنوع (human-like)
        """
        if not sequence or len(sequence) < 2:
            return 0.0

        try:
            # شوف كل عنصر بيتكرر قد إيه
            counter = Counter(
                str(x) for x in sequence
            )

            total = len(sequence)
            max_freq = max(counter.values())

            # لو كل العناصر فريدة → score=0
            # لو عنصر واحد بس متكرر → score قريب من 1
            if max_freq == 1:
                return 0.0

            return float(min((max_freq - 1) / (total - 1), 1.0))
        except (TypeError, ValueError, ZeroDivisionError):
            return 0.0

    # ═══════════════════════════════════════════════════════
    #  Sequential ID Detection
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def extract_numeric_ids(sequence: List[Any]) -> List[int]:
        """بيستخرج الأرقام من sequence."""
        ids = []
        for item in sequence:
            try:
                num = int(item)
                ids.append(num)
            except (ValueError, TypeError):
                # جرب نستخرج رقم من string
                if isinstance(item, str):
                    match = re.search(r"\d+", item)
                    if match:
                        try:
                            ids.append(int(match.group()))
                        except ValueError:
                            continue
        return ids

    @classmethod
    def sequential_id_score(cls, sequence: List[Any]) -> float:
        """
        بيكشف الـ sequential IDs (1, 2, 3, ...).

        Returns:
            score (0-1) — أعلى score = more sequential
        """
        ids = cls.extract_numeric_ids(sequence)

        if len(ids) < cls.MIN_SEQUENCE_LENGTH:
            return 0.0

        # احسب عدد المرات اللي الـ IDs متتالية
        sequential_count = 0
        for i in range(len(ids) - 1):
            diff = ids[i + 1] - ids[i]
            # نقبل +1 أو +2 أو -1 أو -2
            if diff in (1, 2, -1, -2):
                sequential_count += 1

        ratio = sequential_count / (len(ids) - 1)

        return float(min(max(ratio, 0.0), 1.0))

    # ═══════════════════════════════════════════════════════
    #  Markov Chain
    # ═══════════════════════════════════════════════════════

    @classmethod
    def markov_entropy(cls, sequence: List[Any]) -> float:
        """
        بيكشف entropy الانتقالات في Markov chain.

        entropy منخفض = transitions قابلة للتنبؤ (bot-like)
        entropy عالي = transitions عشوائية (human-like)

        ملاحظة:
        - بنحسب conditional entropy H(next|current) موزون
        - بنتجاهل الـ states اللي ظهرت مرة واحدة بس (entropy مضللة)
        - لو مفيش states بتتكرر → fallback لـ unconditional entropy
        """
        if not sequence or len(sequence) < 3:
            return 0.0

        try:
            # احسب transitions + counts
            transitions: Dict[str, Counter] = {}
            state_counts: Counter = Counter()

            for i in range(len(sequence) - 1):
                current = str(sequence[i])
                next_item = str(sequence[i + 1])

                state_counts[current] += 1

                if current not in transitions:
                    transitions[current] = Counter()
                transitions[current][next_item] += 1

            if not transitions:
                return 0.0

            # احسب conditional entropy لكل state
            # بس للـ states اللي ظهرت 2+ مرات
            entropies: List[float] = []
            weights: List[int] = []

            for current, next_counter in transitions.items():
                count = state_counts[current]

                # لو الـ state ظهر مرة واحدة بس
                # conditional entropy = 0 (مضللة) → نتجاهلها
                if count < 2:
                    continue

                total = sum(next_counter.values())
                if total == 0:
                    continue

                entropy = 0.0
                for cnt in next_counter.values():
                    p = cnt / total
                    if p > 0:
                        entropy -= p * math.log2(p)

                entropies.append(entropy)
                weights.append(count)

            # ─── Fallback ───
            # لو مفيش states بتتكرر (كل العناصر فريدة)
            # بنرجع unconditional entropy لتوزيع الـ transitions
            if not entropies:
                all_counts: List[int] = []
                for next_counter in transitions.values():
                    all_counts.extend(next_counter.values())

                if len(all_counts) < 2:
                    return 0.0

                total = sum(all_counts)
                if total == 0:
                    return 0.0

                h = 0.0
                for cnt in all_counts:
                    p = cnt / total
                    if p > 0:
                        h -= p * math.log2(p)

                return float(h)

            # ─── Weighted average ───
            total_weight = sum(weights)
            if total_weight == 0:
                return 0.0

            weighted = sum(
                e * w for e, w in zip(entropies, weights)
            ) / total_weight

            return float(weighted)
        except (TypeError, ValueError, ZeroDivisionError):
            return 0.0

    # ═══════════════════════════════════════════════════════
    #  Periodic Pattern Detection
    # ═══════════════════════════════════════════════════════

    @classmethod
    def periodic_score(cls, sequence: List[Any]) -> float:
        """
        بيكشف الـ periodicity.

        = وجود نمط بيتكرر كل فترة ثابتة.
        """
        if not sequence or len(sequence) < 4:
            return 0.0

        try:
            # حوّل لـ string
            seq_str = [str(x) for x in sequence]

            n = len(seq_str)
            best_score = 0.0

            # جرب كل فترة ممكنة (2 → n/2)
            for period in range(2, n // 2 + 1):
                matches = 0
                comparisons = 0

                for i in range(n - period):
                    comparisons += 1
                    if seq_str[i] == seq_str[i + period]:
                        matches += 1

                if comparisons > 0:
                    score = matches / comparisons
                    if score > best_score:
                        best_score = score

            return float(min(best_score, 1.0))
        except (TypeError, ValueError, ZeroDivisionError):
            return 0.0

    # ═══════════════════════════════════════════════════════
    #  Compression Ratio (Sequence)
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def compression_ratio(sequence: List[Any]) -> float:
        """
        نسبة ضغط الـ sequence.

        منخفض = تكرار كتير
        عالي = تنوع
        """
        if not sequence:
            return 1.0

        try:
            import zlib
            # حوّل sequence لـ string
            seq_str = "|".join(str(x) for x in sequence)
            raw_bytes = seq_str.encode("utf-8", errors="replace")

            if len(raw_bytes) == 0:
                return 1.0

            compressed = zlib.compress(raw_bytes, level=6)
            ratio = len(compressed) / len(raw_bytes)

            return float(min(max(ratio, 0.0), 1.0))
        except (TypeError, ValueError, zlib.error):
            return 1.0

    # ═══════════════════════════════════════════════════════
    #  Common Prefix
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def common_prefix_length(strings: List[str]) -> int:
        """بيرجع طول أطول prefix مشترك."""
        if not strings:
            return 0

        try:
            strings = [str(s) for s in strings]
            if not strings:
                return 0

            prefix_len = 0
            first = strings[0]
            max_len = min(len(s) for s in strings)

            for i in range(max_len):
                char = first[i]
                if all(s[i] == char for s in strings):
                    prefix_len += 1
                else:
                    break

            return prefix_len
        except (TypeError, ValueError, IndexError):
            return 0

    @classmethod
    def avg_common_prefix_ratio(cls, strings: List[str]) -> float:
        """متوسط نسبة الـ common prefix."""
        if not strings or len(strings) < 2:
            return 0.0

        try:
            prefix_len = cls.common_prefix_length(strings)
            avg_len = sum(len(str(s)) for s in strings) / len(strings)

            if avg_len <= 0:
                return 0.0

            return float(prefix_len / avg_len)
        except (TypeError, ValueError, ZeroDivisionError):
            return 0.0

    # ═══════════════════════════════════════════════════════
    #  Transition Uniformity
    # ═══════════════════════════════════════════════════════

    @classmethod
    def transition_uniformity(cls, sequence: List[Any]) -> float:
        """
        بيقيس مدى انتظام الانتقالات.

        عالي = transitions منتظمة (bot)
        منخفض = transitions عشوائية
        """
        if not sequence or len(sequence) < 3:
            return 0.0

        try:
            # احسب الـ differences بين العناصر المتتالية (لو أرقام)
            ids = cls.extract_numeric_ids(sequence)

            if len(ids) < 3:
                return 0.0

            diffs = [ids[i + 1] - ids[i] for i in range(len(ids) - 1)]

            if not diffs:
                return 0.0

            # لو كل الـ diffs متشابهة → uniformity عالي
            most_common = Counter(diffs).most_common(1)
            if not most_common:
                return 0.0

            most_common_count = most_common[0][1]
            uniformity = most_common_count / len(diffs)

            return float(min(uniformity, 1.0))
        except (TypeError, ValueError, ZeroDivisionError):
            return 0.0

    # ═══════════════════════════════════════════════════════
    #  Main: Extract All Features
    # ═══════════════════════════════════════════════════════

    @classmethod
    def extract(
        cls,
        sequence: List[Any],
        ngram_sizes: Optional[List[int]] = None,
    ) -> Dict[str, float]:
        """
        بيستخرج كل الـ sequence features.

        Args:
            sequence: قائمة عناصر
            ngram_sizes: أحجام n-grams (افتراضي: [2, 3, 4])

        Returns:
            dict فيه كل الـ features
        """
        features: Dict[str, float] = {}

        if not sequence:
            for name in cls.FEATURE_NAMES:
                features[name] = 0.0
            return features

        ngram_sizes = ngram_sizes or cls.DEFAULT_NGRAM_SIZES

        # 1. Basic features
        length = float(len(sequence))
        unique_ratio = cls.unique_ratio(sequence)

        # 2. N-gram features
        ngram_entropies = []
        ngram_counts = []
        ngram_max_freqs = []

        for n in ngram_sizes:
            stats = cls.ngram_stats(sequence, n)
            if stats["count"] > 0:
                ngram_entropies.append(stats["entropy"])
                ngram_counts.append(stats["count"])
                ngram_max_freqs.append(stats["max_freq"])

        avg_ngram_count = float(np.mean(ngram_counts)) if ngram_counts else 0.0
        max_ngram_count = float(max(ngram_counts)) if ngram_counts else 0.0
        ngram_entropy = float(np.mean(ngram_entropies)) if ngram_entropies else 0.0

        # 3. Repetition
        repetition = cls.repetition_score(sequence)

        # 4. Sequential IDs
        seq_id = cls.sequential_id_score(sequence)

        # 5. Markov
        markov = cls.markov_entropy(sequence)

        # 6. Periodic
        periodic = cls.periodic_score(sequence)

        # 7. Compression
        compression = cls.compression_ratio(sequence)

        # 8. Common prefix
        strings = [str(x) for x in sequence]
        prefix_len = cls.common_prefix_length(strings)
        prefix_ratio = cls.avg_common_prefix_ratio(strings)

        # 9. Transition uniformity
        transition = cls.transition_uniformity(sequence)

        features.update({
            "length": length,
            "unique_ratio": unique_ratio,
            "avg_ngram_count": avg_ngram_count,
            "max_ngram_count": max_ngram_count,
            "ngram_entropy": ngram_entropy,
            "repetition_score": repetition,
            "sequential_id_score": seq_id,
            "markov_entropy": markov,
            "periodic_score": periodic,
            "compression_ratio": compression,
            "common_prefix_length": float(prefix_len),
            "avg_common_prefix_ratio": prefix_ratio,
            "transition_uniformity": transition,
        })

        return features

    @classmethod
    def extract_as_vector(
        cls,
        sequence: List[Any],
    ) -> np.ndarray:
        """بيستخرج الـ features كـ numpy vector."""
        features = cls.extract(sequence)
        return np.array(
            [features[name] for name in cls.FEATURE_NAMES],
            dtype=np.float32,
        )

    @classmethod
    def get_feature_names(cls) -> List[str]:
        """بيرجع أسماء الـ features."""
        return list(cls.FEATURE_NAMES)

    # ═══════════════════════════════════════════════════════
    #  High-Level Helpers
    # ═══════════════════════════════════════════════════════

    @classmethod
    def is_automated(cls, sequence: List[Any]) -> Dict[str, Any]:
        """
        بيحدد لو الـ sequence automated (bot-like).

        Returns:
            dict فيه: is_automated, confidence, reasons
        """
        if not sequence or len(sequence) < cls.MIN_SEQUENCE_LENGTH:
            return {
                "is_automated": False,
                "confidence": 0.0,
                "reasons": [],
            }

        features = cls.extract(sequence)
        reasons = []
        score = 0.0

        # 1. Sequential IDs
        if features["sequential_id_score"] > 0.7:
            reasons.append("sequential_ids")
            score += 35

        # 2. Repetition
        if features["repetition_score"] > 0.5:
            reasons.append("high_repetition")
            score += 25

        # 3. Periodic
        if features["periodic_score"] > 0.7:
            reasons.append("periodic_pattern")
            score += 25

        # 4. Low markov entropy
        if 0 < features["markov_entropy"] < 0.5:
            reasons.append("low_transition_entropy")
            score += 20

        # 5. Low compression (highly repetitive)
        if features["compression_ratio"] < 0.3:
            reasons.append("very_compressible")
            score += 15

        # 6. High transition uniformity
        if features["transition_uniformity"] > 0.7:
            reasons.append("uniform_transitions")
            score += 20

        confidence = min(score, 100)

        return {
            "is_automated": confidence >= 50,
            "confidence": confidence,
            "reasons": reasons,
            "features": features,
        }

    @classmethod
    def compare_sequences(
        cls,
        seq1: List[Any],
        seq2: List[Any],
    ) -> Dict[str, Any]:
        """بيقارن sequenceين."""
        f1 = cls.extract(seq1)
        f2 = cls.extract(seq2)

        common_features = [
            "unique_ratio", "repetition_score",
            "sequential_id_score", "markov_entropy",
            "periodic_score",
        ]

        differences = {}
        total_diff = 0.0

        for name in common_features:
            v1 = f1.get(name, 0.0)
            v2 = f2.get(name, 0.0)
            diff = abs(v1 - v2)
            differences[name] = diff
            total_diff += diff

        avg_diff = total_diff / len(common_features) if common_features else 0.0

        return {
            "avg_difference": float(avg_diff),
            "is_similar": avg_diff < 0.2,
            "differences": differences,
        }


# ─── Standalone functions ─────────────────────────────

def extract_ngrams(sequence: List[Any], n: int = 2) -> List[Tuple]:
    """Shortcut for SequenceFeatures.extract_ngrams."""
    return SequenceFeatures.extract_ngrams(sequence, n)


def unique_ratio(sequence: List[Any]) -> float:
    """Shortcut for SequenceFeatures.unique_ratio."""
    return SequenceFeatures.unique_ratio(sequence)


def repetition_score(sequence: List[Any]) -> float:
    """Shortcut for SequenceFeatures.repetition_score."""
    return SequenceFeatures.repetition_score(sequence)


def sequential_id_score(sequence: List[Any]) -> float:
    """Shortcut for SequenceFeatures.sequential_id_score."""
    return SequenceFeatures.sequential_id_score(sequence)


def extract_sequence_features(sequence: List[Any]) -> Dict[str, float]:
    """Shortcut for SequenceFeatures.extract."""
    return SequenceFeatures.extract(sequence)


def is_automated(sequence: List[Any]) -> Dict[str, Any]:
    """Shortcut for SequenceFeatures.is_automated."""
    return SequenceFeatures.is_automated(sequence)