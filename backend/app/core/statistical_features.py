"""
Statistical Features — Statistical feature extraction for ML models.

بيوفر:
- Basic statistics (mean, median, mode, std, var)
- Percentiles (25, 50, 75, 90, 95, 99)
- Interquartile range (IQR)
- Range, min, max
- Skewness & Kurtosis
- Outlier detection (z-score, IQR method)
- Distribution shape analysis
- Coefficient of variation
- Gini coefficient
- Histogram features

الفكرة:
- بيستخرج features إحصائية من arrays (distributions)
- Features بتُستخدم من ML models للـ anomaly detection
- بتساعد في كشف الـ patterns المشبوهة

الاستخدام:
- anomaly_detection.py
- ensemble_anomaly.py
- user_baseline.py
- peer_analysis.py
- feature_extractor.py
"""

from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import structlog

logger = structlog.get_logger()


class StatisticalFeatures:
    """
    Statistical Feature Extraction.

    بيستخرج features إحصائية من arrays.
    """

    # ─── Config ────────────────────────────────────────────
    MIN_SAMPLES = 2
    OUTLIER_Z_THRESHOLD = 3.0
    OUTLIER_IQR_MULTIPLIER = 1.5

    # ─── Feature Names ────────────────────────────────────
    FEATURE_NAMES = [
        "mean", "median", "mode", "std", "variance",
        "min", "max", "range", "sum",
        "p25", "p50", "p75", "p90", "p95", "p99",
        "iqr", "lower_fence", "upper_fence",
        "skewness", "kurtosis",
        "coeff_variation", "gini_coefficient",
        "outlier_ratio", "sample_count",
    ]

    # ═══════════════════════════════════════════════════════
    #  Basic Statistics
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def mean(values: List[float]) -> float:
        """المتوسط الحسابي."""
        if not values:
            return 0.0
        try:
            return float(np.mean(values))
        except (ValueError, TypeError):
            return 0.0

    @staticmethod
    def median(values: List[float]) -> float:
        """الوسيط."""
        if not values:
            return 0.0
        try:
            return float(np.median(values))
        except (ValueError, TypeError):
            return 0.0

    @staticmethod
    def mode(values: List[float]) -> float:
        """المنوال (القيمة الأكثر تكراراً)."""
        if not values:
            return 0.0
        try:
            from collections import Counter
            counter = Counter(values)
            if not counter:
                return 0.0
            most_common = counter.most_common(1)
            return float(most_common[0][0]) if most_common else 0.0
        except (ValueError, TypeError):
            return 0.0

    @staticmethod
    def std(values: List[float]) -> float:
        """الانحراف المعياري."""
        if not values or len(values) < 2:
            return 0.0
        try:
            return float(np.std(values, ddof=0))
        except (ValueError, TypeError):
            return 0.0

    @staticmethod
    def variance(values: List[float]) -> float:
        """التباين."""
        if not values or len(values) < 2:
            return 0.0
        try:
            return float(np.var(values, ddof=0))
        except (ValueError, TypeError):
            return 0.0

    @staticmethod
    def min_value(values: List[float]) -> float:
        """أصغر قيمة."""
        if not values:
            return 0.0
        try:
            return float(np.min(values))
        except (ValueError, TypeError):
            return 0.0

    @staticmethod
    def max_value(values: List[float]) -> float:
        """أكبر قيمة."""
        if not values:
            return 0.0
        try:
            return float(np.max(values))
        except (ValueError, TypeError):
            return 0.0

    @classmethod
    def range_value(cls, values: List[float]) -> float:
        """المدى (max - min)."""
        if not values:
            return 0.0
        return cls.max_value(values) - cls.min_value(values)

    @staticmethod
    def sum_value(values: List[float]) -> float:
        """المجموع."""
        if not values:
            return 0.0
        try:
            return float(np.sum(values))
        except (ValueError, TypeError):
            return 0.0

    # ═══════════════════════════════════════════════════════
    #  Percentiles
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def percentile(values: List[float], p: float) -> float:
        """بيحسب percentile معين."""
        if not values:
            return 0.0
        try:
            return float(np.percentile(values, p))
        except (ValueError, TypeError):
            return 0.0

    @classmethod
    def percentiles(
        cls,
        values: List[float],
        percentiles: Optional[List[float]] = None,
    ) -> Dict[str, float]:
        """
        بيحسب مجموعة percentiles.

        Returns:
            dict فيه p25, p50, p75, ...
        """
        if percentiles is None:
            percentiles = [25, 50, 75, 90, 95, 99]

        result = {}
        for p in percentiles:
            result[f"p{int(p)}"] = cls.percentile(values, p)

        return result

    # ═══════════════════════════════════════════════════════
    #  IQR & Outliers
    # ═══════════════════════════════════════════════════════

    @classmethod
    def iqr(cls, values: List[float]) -> float:
        """Interquartile Range = p75 - p25."""
        if not values:
            return 0.0
        p75 = cls.percentile(values, 75)
        p25 = cls.percentile(values, 25)
        return p75 - p25

    @classmethod
    def iqr_fences(
        cls,
        values: List[float],
        multiplier: float = OUTLIER_IQR_MULTIPLIER,
    ) -> Tuple[float, float]:
        """
        بيرجع (lower_fence, upper_fence) للـ IQR method.
        """
        if not values:
            return 0.0, 0.0

        p25 = cls.percentile(values, 25)
        p75 = cls.percentile(values, 75)
        iqr = p75 - p25

        lower = p25 - multiplier * iqr
        upper = p75 + multiplier * iqr

        return float(lower), float(upper)

    @classmethod
    def find_outliers_iqr(
        cls,
        values: List[float],
        multiplier: float = OUTLIER_IQR_MULTIPLIER,
    ) -> List[int]:
        """
        بيلاقي outliers بـ IQR method.

        Returns:
            قائمة indices
        """
        if not values or len(values) < 4:
            return []

        lower, upper = cls.iqr_fences(values, multiplier)

        outliers = []
        for i, v in enumerate(values):
            if v < lower or v > upper:
                outliers.append(i)

        return outliers

    @classmethod
    def find_outliers_zscore(
        cls,
        values: List[float],
        threshold: float = OUTLIER_Z_THRESHOLD,
    ) -> List[int]:
        """
        بيلاقي outliers بـ z-score method.

        Returns:
            قائمة indices
        """
        if not values or len(values) < 3:
            return []

        try:
            arr = np.array(values, dtype=np.float64)
            mean = np.mean(arr)
            std = np.std(arr)

            if std == 0:
                return []

            z_scores = np.abs((arr - mean) / std)

            return [int(i) for i in np.where(z_scores > threshold)[0]]
        except (ValueError, TypeError):
            return []

    @classmethod
    def outlier_ratio(
        cls,
        values: List[float],
        method: str = "iqr",
    ) -> float:
        """
        نسبة الـ outliers.

        Args:
            method: "iqr" أو "zscore"
        """
        if not values or len(values) < 3:
            return 0.0

        if method == "iqr":
            outliers = cls.find_outliers_iqr(values)
        else:
            outliers = cls.find_outliers_zscore(values)

        return len(outliers) / len(values)

    # ═══════════════════════════════════════════════════════
    #  Distribution Shape
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def skewness(values: List[float]) -> float:
        """
        Skewness (التواء التوزيع).

        - 0 = symmetric
        - > 0 = right-skewed (tail on right)
        - < 0 = left-skewed (tail on left)
        """
        if not values or len(values) < 3:
            return 0.0

        try:
            arr = np.array(values, dtype=np.float64)
            mean = np.mean(arr)
            std = np.std(arr)

            if std == 0:
                return 0.0

            n = len(arr)
            skew = np.sum(((arr - mean) / std) ** 3) / n

            return float(skew)
        except (ValueError, TypeError):
            return 0.0

    @staticmethod
    def kurtosis(values: List[float]) -> float:
        """
        Kurtosis (تفرطح التوزيع).

        - 0 = normal (mesokurtic)
        - > 0 = heavy tails (leptokurtic)
        - < 0 = light tails (platykurtic)
        """
        if not values or len(values) < 4:
            return 0.0

        try:
            arr = np.array(values, dtype=np.float64)
            mean = np.mean(arr)
            std = np.std(arr)

            if std == 0:
                return 0.0

            n = len(arr)
            kurt = np.sum(((arr - mean) / std) ** 4) / n - 3.0

            return float(kurt)
        except (ValueError, TypeError):
            return 0.0

    # ═══════════════════════════════════════════════════════
    #  Coefficients
    # ═══════════════════════════════════════════════════════

    @classmethod
    def coefficient_of_variation(cls, values: List[float]) -> float:
        """
        Coefficient of Variation = std / mean.

        بيقيس relative variability.
        """
        if not values or len(values) < 2:
            return 0.0

        mean = cls.mean(values)
        if mean == 0:
            return 0.0

        std = cls.std(values)

        return float(abs(std / mean))

    @staticmethod
    def gini_coefficient(values: List[float]) -> float:
        """
        Gini Coefficient (0 = perfect equality, 1 = perfect inequality).

        بيقيس مدى عدم المساواة في التوزيع.
        """
        if not values or len(values) < 2:
            return 0.0

        try:
            arr = np.sort(np.array(values, dtype=np.float64))
            n = len(arr)

            if np.sum(arr) == 0:
                return 0.0

            # Gini formula
            index = np.arange(1, n + 1)
            gini = (
                (2 * np.sum(index * arr)) / (n * np.sum(arr))
                - (n + 1) / n
            )

            return float(abs(gini))
        except (ValueError, TypeError):
            return 0.0

    # ═══════════════════════════════════════════════════════
    #  Main: Extract All Features
    # ═══════════════════════════════════════════════════════

    @classmethod
    def extract(cls, values: List[float]) -> Dict[str, float]:
        """
        بيستخرج كل الـ statistical features.

        Args:
            values: قائمة أرقام

        Returns:
            dict فيه كل الـ features
        """
        features: Dict[str, float] = {}

        if not values:
            for name in cls.FEATURE_NAMES:
                features[name] = 0.0
            return features

        # 1. Basic statistics
        mean_val = cls.mean(values)
        median_val = cls.median(values)
        mode_val = cls.mode(values)
        std_val = cls.std(values)
        var_val = cls.variance(values)
        min_val = cls.min_value(values)
        max_val = cls.max_value(values)
        range_val = cls.range_value(values)
        sum_val = cls.sum_value(values)

        # 2. Percentiles
        percentiles = cls.percentiles(values)

        # 3. IQR
        iqr_val = cls.iqr(values)
        lower, upper = cls.iqr_fences(values)

        # 4. Shape
        skew = cls.skewness(values)
        kurt = cls.kurtosis(values)

        # 5. Coefficients
        cv = cls.coefficient_of_variation(values)
        gini = cls.gini_coefficient(values)

        # 6. Outliers
        outlier_ratio = cls.outlier_ratio(values)

        features.update({
            "mean": mean_val,
            "median": median_val,
            "mode": mode_val,
            "std": std_val,
            "variance": var_val,
            "min": min_val,
            "max": max_val,
            "range": range_val,
            "sum": sum_val,

            "p25": percentiles.get("p25", 0.0),
            "p50": percentiles.get("p50", 0.0),
            "p75": percentiles.get("p75", 0.0),
            "p90": percentiles.get("p90", 0.0),
            "p95": percentiles.get("p95", 0.0),
            "p99": percentiles.get("p99", 0.0),

            "iqr": iqr_val,
            "lower_fence": lower,
            "upper_fence": upper,

            "skewness": skew,
            "kurtosis": kurt,
            "coeff_variation": cv,
            "gini_coefficient": gini,
            "outlier_ratio": outlier_ratio,
            "sample_count": float(len(values)),
        })

        return features

    @classmethod
    def extract_as_vector(cls, values: List[float]) -> np.ndarray:
        """بيستخرج الـ features كـ numpy vector."""
        features = cls.extract(values)
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
    def compare_distributions(
        cls,
        values1: List[float],
        values2: List[float],
    ) -> Dict[str, Any]:
        """
        بيقارن توزيعين.

        Returns:
            dict فيه: mean_diff, std_diff, similar
        """
        if not values1 or not values2:
            return {
                "valid": False,
                "reason": "empty_values",
            }

        features1 = cls.extract(values1)
        features2 = cls.extract(values2)

        # احسب الفروق
        mean_diff = abs(features1["mean"] - features2["mean"])
        std_diff = abs(features1["std"] - features2["std"])

        # نسبة التشابه
        # لو mean قريب من الصفر، اعتبرهم مختلفين
        if max(abs(features1["mean"]), abs(features2["mean"])) < 0.001:
            mean_ratio = 0.0 if mean_diff > 0.001 else 1.0
        else:
            max_mean = max(abs(features1["mean"]), abs(features2["mean"]))
            mean_ratio = 1.0 - min(mean_diff / max_mean, 1.0)

        max_std = max(features1["std"], features2["std"])
        if max_std < 0.001:
            std_ratio = 1.0
        else:
            std_ratio = 1.0 - min(std_diff / max_std, 1.0)

        # اجمع
        similarity = (mean_ratio + std_ratio) / 2.0

        return {
            "valid": True,
            "mean_diff": float(mean_diff),
            "std_diff": float(std_diff),
            "similarity": float(similarity),
            "is_similar": similarity > 0.8,
            "features1": features1,
            "features2": features2,
        }

    @classmethod
    def detect_anomalous_distribution(
        cls,
        values: List[float],
    ) -> Dict[str, Any]:
        """
        بيكشف لو التوزيع غير طبيعي.

        Returns:
            dict فيه: is_anomalous, reasons, score
        """
        if not values or len(values) < 3:
            return {
                "is_anomalous": False,
                "score": 0.0,
                "reasons": [],
            }

        features = cls.extract(values)
        reasons = []
        score = 0.0

        # 1. outliers كتير
        if features["outlier_ratio"] > 0.2:
            reasons.append("high_outlier_ratio")
            score += 30
        elif features["outlier_ratio"] > 0.1:
            reasons.append("moderate_outlier_ratio")
            score += 15

        # 2. skewness عالي
        if abs(features["skewness"]) > 2.0:
            reasons.append("high_skewness")
            score += 25

        # 3. kurtosis عالي
        if abs(features["kurtosis"]) > 5.0:
            reasons.append("high_kurtosis")
            score += 25

        # 4. coefficient of variation عالي
        if features["coeff_variation"] > 1.0:
            reasons.append("high_variability")
            score += 20

        # 5. gini عالي (عدم مساواة كبيرة)
        if features["gini_coefficient"] > 0.5:
            reasons.append("high_inequality")
            score += 15

        return {
            "is_anomalous": score >= 50,
            "score": min(score, 100),
            "reasons": reasons,
            "features": features,
        }


# ─── Standalone functions ─────────────────────────────

def mean(values: List[float]) -> float:
    """Shortcut for StatisticalFeatures.mean."""
    return StatisticalFeatures.mean(values)


def median(values: List[float]) -> float:
    """Shortcut for StatisticalFeatures.median."""
    return StatisticalFeatures.median(values)


def std(values: List[float]) -> float:
    """Shortcut for StatisticalFeatures.std."""
    return StatisticalFeatures.std(values)


def extract_statistical_features(values: List[float]) -> Dict[str, float]:
    """Shortcut for StatisticalFeatures.extract."""
    return StatisticalFeatures.extract(values)


def find_outliers_iqr(values: List[float]) -> List[int]:
    """Shortcut for StatisticalFeatures.find_outliers_iqr."""
    return StatisticalFeatures.find_outliers_iqr(values)


def coefficient_of_variation(values: List[float]) -> float:
    """Shortcut for StatisticalFeatures.coefficient_of_variation."""
    return StatisticalFeatures.coefficient_of_variation(values)