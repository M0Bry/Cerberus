"""
Feature Extractor — Unified feature extraction orchestrator.

بيوفر:
- Unified interface لكل feature extractors
- Feature aggregation (temporal + entropy + statistical + sequence + geographic)
- Feature normalization & scaling
- Feature selection
- Feature vector generation (للـ ML models)
- Named feature groups
- Extraction modes (payload, request, user, session)

الفكرة:
- بينسق بين كل الـ feature extractors
- بيرجع feature vector موحد للـ ML models
- بيدعم feature groups مختارة

الاستخدام:
- ml_payload_detector.py
- anomaly_detection.py
- ensemble_anomaly.py
- user_baseline.py
- session_analyzer.py
- attack_chain.py
"""

from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import structlog

from app.core.entropy_features import EntropyFeatures
from app.core.geographic_features import GeographicFeatures
from app.core.sequence_features import SequenceFeatures
from app.core.statistical_features import StatisticalFeatures
from app.core.temporal_features import TemporalFeatures

logger = structlog.get_logger()


class FeatureExtractor:
    """
    Unified Feature Extractor.

    بينسق بين كل الـ feature extractors ويرجع feature vector موحد.
    """

    # ─── Feature Groups ───────────────────────────────────
    GROUPS = {
        "temporal": TemporalFeatures.FEATURE_NAMES,
        "entropy": EntropyFeatures.FEATURE_NAMES,
        "statistical": StatisticalFeatures.FEATURE_NAMES,
        "sequence": SequenceFeatures.FEATURE_NAMES,
        "geographic": GeographicFeatures.FEATURE_NAMES,
    }

    # ─── Total feature count ──────────────────────────────
    TOTAL_FEATURES = sum(len(names) for names in GROUPS.values())

    # ═══════════════════════════════════════════════════════
    #  Feature Names
    # ═══════════════════════════════════════════════════════

    @classmethod
    def get_all_feature_names(cls) -> List[str]:
        """بيرجع كل أسماء الـ features (مع prefixes)."""
        names = []
        for group, features in cls.GROUPS.items():
            for f in features:
                names.append(f"{group}__{f}")
        return names

    @classmethod
    def get_group_feature_names(cls, group: str) -> List[str]:
        """بيرجع أسماء features مجموعة معينة."""
        features = cls.GROUPS.get(group, [])
        return [f"{group}__{f}" for f in features]

    @classmethod
    def get_group_size(cls, group: str) -> int:
        """بيرجع عدد features مجموعة معينة."""
        return len(cls.GROUPS.get(group, []))

    # ═══════════════════════════════════════════════════════
    #  Individual Extractors
    # ═══════════════════════════════════════════════════════

    @classmethod
    def extract_temporal(
        cls,
        timestamps: List[float],
    ) -> Dict[str, float]:
        """بيستخرج temporal features."""
        try:
            feats = TemporalFeatures.extract(timestamps)
            return {
                f"temporal__{k}": v for k, v in feats.items()
            }
        except Exception as e:
            logger.error("extract_temporal_failed", error=str(e))
            return {
                f"temporal__{n}": 0.0
                for n in TemporalFeatures.FEATURE_NAMES
            }

    @classmethod
    def extract_entropy(
        cls,
        text: str,
    ) -> Dict[str, float]:
        """بيستخرج entropy features."""
        try:
            feats = EntropyFeatures.extract(text)
            return {
                f"entropy__{k}": v for k, v in feats.items()
            }
        except Exception as e:
            logger.error("extract_entropy_failed", error=str(e))
            return {
                f"entropy__{n}": 0.0
                for n in EntropyFeatures.FEATURE_NAMES
            }

    @classmethod
    def extract_statistical(
        cls,
        values: List[float],
    ) -> Dict[str, float]:
        """بيستخرج statistical features."""
        try:
            feats = StatisticalFeatures.extract(values)
            return {
                f"statistical__{k}": v for k, v in feats.items()
            }
        except Exception as e:
            logger.error("extract_statistical_failed", error=str(e))
            return {
                f"statistical__{n}": 0.0
                for n in StatisticalFeatures.FEATURE_NAMES
            }

    @classmethod
    def extract_sequence(
        cls,
        sequence: List[Any],
    ) -> Dict[str, float]:
        """بيستخرج sequence features."""
        try:
            feats = SequenceFeatures.extract(sequence)
            return {
                f"sequence__{k}": v for k, v in feats.items()
            }
        except Exception as e:
            logger.error("extract_sequence_failed", error=str(e))
            return {
                f"sequence__{n}": 0.0
                for n in SequenceFeatures.FEATURE_NAMES
            }

    @classmethod
    def extract_geographic(
        cls,
        locations: List[Dict[str, Any]],
    ) -> Dict[str, float]:
        """بيستخرج geographic features."""
        try:
            feats = GeographicFeatures.extract(locations)
            return {
                f"geographic__{k}": v for k, v in feats.items()
            }
        except Exception as e:
            logger.error("extract_geographic_failed", error=str(e))
            return {
                f"geographic__{n}": 0.0
                for n in GeographicFeatures.FEATURE_NAMES
            }

    # ═══════════════════════════════════════════════════════
    #  Main: Unified Extraction
    # ═══════════════════════════════════════════════════════

    @classmethod
    def extract_all(
        cls,
        *,
        timestamps: Optional[List[float]] = None,
        text: Optional[str] = None,
        values: Optional[List[float]] = None,
        sequence: Optional[List[Any]] = None,
        locations: Optional[List[Dict[str, Any]]] = None,
        groups: Optional[List[str]] = None,
    ) -> Dict[str, float]:
        """
        بيستخرج features من كل المصادر المحددة.

        Args:
            timestamps: للـ temporal features
            text: للـ entropy features
            values: للـ statistical features
            sequence: للـ sequence features
            locations: للـ geographic features
            groups: اختياري — تحديد مجموعات معينة
                    (temporal, entropy, statistical, sequence, geographic)

        Returns:
            dict فيه كل الـ features (مع prefixes)
        """
        selected_groups = groups or list(cls.GROUPS.keys())
        features: Dict[str, float] = {}

        # 1. Temporal
        if "temporal" in selected_groups:
            if timestamps:
                features.update(cls.extract_temporal(timestamps))
            else:
                features.update({
                    f"temporal__{n}": 0.0
                    for n in TemporalFeatures.FEATURE_NAMES
                })

        # 2. Entropy
        if "entropy" in selected_groups:
            if text:
                features.update(cls.extract_entropy(text))
            else:
                features.update({
                    f"entropy__{n}": 0.0
                    for n in EntropyFeatures.FEATURE_NAMES
                })

        # 3. Statistical
        if "statistical" in selected_groups:
            if values:
                features.update(cls.extract_statistical(values))
            else:
                features.update({
                    f"statistical__{n}": 0.0
                    for n in StatisticalFeatures.FEATURE_NAMES
                })

        # 4. Sequence
        if "sequence" in selected_groups:
            if sequence:
                features.update(cls.extract_sequence(sequence))
            else:
                features.update({
                    f"sequence__{n}": 0.0
                    for n in SequenceFeatures.FEATURE_NAMES
                })

        # 5. Geographic
        if "geographic" in selected_groups:
            if locations:
                features.update(cls.extract_geographic(locations))
            else:
                features.update({
                    f"geographic__{n}": 0.0
                    for n in GeographicFeatures.FEATURE_NAMES
                })

        return features

    # ═══════════════════════════════════════════════════════
    #  Feature Vector
    # ═══════════════════════════════════════════════════════

    @classmethod
    def extract_vector(
        cls,
        *,
        timestamps: Optional[List[float]] = None,
        text: Optional[str] = None,
        values: Optional[List[float]] = None,
        sequence: Optional[List[Any]] = None,
        locations: Optional[List[Dict[str, Any]]] = None,
        groups: Optional[List[str]] = None,
        clip_range: Optional[Tuple[float, float]] = None,
    ) -> np.ndarray:
        """
        بيرجع feature vector موحد للـ ML.

        Args:
            clip_range: (min, max) لقص القيم الشاذة

        Returns:
            numpy array (float32)
        """
        features = cls.extract_all(
            timestamps=timestamps,
            text=text,
            values=values,
            sequence=sequence,
            locations=locations,
            groups=groups,
        )

        # احصل على أسماء الـ features بالترتيب
        if groups:
            names = []
            for g in groups:
                names.extend(cls.get_group_feature_names(g))
        else:
            names = cls.get_all_feature_names()

        # ابنِ الـ vector
        vec = np.array(
            [features.get(name, 0.0) for name in names],
            dtype=np.float32,
        )

        # clip القيم الشاذة
        if clip_range is not None:
            vec = np.clip(vec, clip_range[0], clip_range[1])

        # عالج NaN و inf
        vec = np.nan_to_num(vec, nan=0.0, posinf=0.0, neginf=0.0)

        return vec

    # ═══════════════════════════════════════════════════════
    #  Normalization
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def normalize_vector(
        vec: np.ndarray,
        method: str = "minmax",
        bounds: Optional[Tuple[float, float]] = None,
    ) -> np.ndarray:
        """
        بيعمل normalize للـ feature vector.

        Args:
            method: "minmax" | "zscore" | "l2"
            bounds: (min, max) للـ minmax method

        Returns:
            normalized vector
        """
        if vec.size == 0:
            return vec

        try:
            if method == "minmax":
                v_min = bounds[0] if bounds else float(np.min(vec))
                v_max = bounds[1] if bounds else float(np.max(vec))

                if v_max - v_min == 0:
                    return np.zeros_like(vec)

                return (vec - v_min) / (v_max - v_min)

            if method == "zscore":
                mean = float(np.mean(vec))
                std = float(np.std(vec))

                if std == 0:
                    return np.zeros_like(vec)

                return (vec - mean) / std

            if method == "l2":
                norm = float(np.linalg.norm(vec))
                if norm == 0:
                    return vec
                return vec / norm

            return vec
        except (ValueError, ZeroDivisionError):
            return vec

    # ═══════════════════════════════════════════════════════
    #  Feature Selection
    # ═══════════════════════════════════════════════════════

    @classmethod
    def select_features(
        cls,
        features: Dict[str, float],
        selected: List[str],
    ) -> Dict[str, float]:
        """بيختار features معينة."""
        return {
            k: v for k, v in features.items()
            if k in selected
        }

    @classmethod
    def filter_by_group(
        cls,
        features: Dict[str, float],
        group: str,
    ) -> Dict[str, float]:
        """بيفلتر features حسب مجموعة."""
        prefix = f"{group}__"
        return {
            k: v for k, v in features.items()
            if k.startswith(prefix)
        }

    # ═══════════════════════════════════════════════════════
    #  Extraction Modes
    # ═══════════════════════════════════════════════════════

    @classmethod
    def extract_for_payload(
        cls,
        payload: str,
        additional_values: Optional[List[float]] = None,
    ) -> np.ndarray:
        """
        Mode للـ payloads.

        بيستخرج features relevant للـ injection detection:
        - entropy
        - statistical (على character codes)
        - sequence (على tokens)
        """
        # حوّل payload لأرقام (character codes)
        if not additional_values:
            additional_values = [ord(c) for c in payload]

        # tokens من payload
        tokens = payload.split() if payload.strip() else list(payload)

        return cls.extract_vector(
            text=payload,
            values=additional_values,
            sequence=tokens,
            groups=["entropy", "statistical", "sequence"],
        )

    @classmethod
    def extract_for_request(
        cls,
        *,
        timestamps: List[float],
        paths: List[str],
        method_counts: Optional[List[float]] = None,
    ) -> np.ndarray:
        """
        Mode للـ HTTP requests.

        بيستخرج features للـ request analysis.
        """
        return cls.extract_vector(
            timestamps=timestamps,
            values=method_counts or [1.0] * len(timestamps),
            sequence=paths,
            groups=["temporal", "statistical", "sequence"],
        )

    @classmethod
    def extract_for_user(
        cls,
        *,
        login_timestamps: List[float],
        locations: List[Dict[str, Any]],
        user_agents: Optional[List[str]] = None,
    ) -> np.ndarray:
        """
        Mode للـ user behavior.

        بيستخرج features للـ user baseline / ATO detection.
        """
        ua_seq = user_agents or []
        return cls.extract_vector(
            timestamps=login_timestamps,
            locations=locations,
            sequence=ua_seq if ua_seq else None,
            groups=["temporal", "geographic", "sequence"],
        )

    # ═══════════════════════════════════════════════════════
    #  Utilities
    # ═══════════════════════════════════════════════════════

    @classmethod
    def feature_summary(cls) -> Dict[str, Any]:
        """ملخص عن كل الـ features المتاحة."""
        return {
            "total_features": cls.TOTAL_FEATURES,
            "groups": {
                group: len(names)
                for group, names in cls.GROUPS.items()
            },
            "group_names": list(cls.GROUPS.keys()),
        }

    @classmethod
    def feature_count(
        cls,
        groups: Optional[List[str]] = None,
    ) -> int:
        """بيرجع عدد الـ features لمجموعة معينة."""
        if not groups:
            return cls.TOTAL_FEATURES

        return sum(
            len(cls.GROUPS.get(g, []))
            for g in groups
        )


# ─── Standalone functions ─────────────────────────────

def extract_all_features(
    *,
    timestamps: Optional[List[float]] = None,
    text: Optional[str] = None,
    values: Optional[List[float]] = None,
    sequence: Optional[List[Any]] = None,
    locations: Optional[List[Dict[str, Any]]] = None,
    groups: Optional[List[str]] = None,
) -> Dict[str, float]:
    """Shortcut for FeatureExtractor.extract_all."""
    return FeatureExtractor.extract_all(
        timestamps=timestamps,
        text=text,
        values=values,
        sequence=sequence,
        locations=locations,
        groups=groups,
    )


def extract_feature_vector(
    *,
    timestamps: Optional[List[float]] = None,
    text: Optional[str] = None,
    values: Optional[List[float]] = None,
    sequence: Optional[List[Any]] = None,
    locations: Optional[List[Dict[str, Any]]] = None,
    groups: Optional[List[str]] = None,
) -> np.ndarray:
    """Shortcut for FeatureExtractor.extract_vector."""
    return FeatureExtractor.extract_vector(
        timestamps=timestamps,
        text=text,
        values=values,
        sequence=sequence,
        locations=locations,
        groups=groups,
    )


def feature_summary() -> Dict[str, Any]:
    """Shortcut for FeatureExtractor.feature_summary."""
    return FeatureExtractor.feature_summary()