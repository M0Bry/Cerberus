"""
Temporal Features — Time-based feature extraction for ML models.

بيوفر:
- Hour of day features (raw + cyclical)
- Day of week features (raw + cyclical)
- Business hours / weekend detection
- Inter-event intervals (mean, std, min, max)
- Event rate (events/second, events/minute)
- Burst detection (sudden activity spikes)
- Time window density
- Activity regularity score
- Session duration estimation
- Timezone-aware processing

الفكرة:
- بياخد timestamps (Unix) ويستخرج منها features
- Features بتُستخدم من ML models للـ anomaly detection
- Cyclical encoding للمحافظة على العلاقة الدورية

الاستخدام:
- ml_payload_detector.py
- anomaly_detection.py
- ensemble_anomaly.py
- user_baseline.py
- session_analyzer.py
- feature_extractor.py
"""

import math
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import structlog

logger = structlog.get_logger()


class TemporalFeatures:
    """
    Temporal Feature Extraction.

    بيستخرج features زمنية من timestamps.
    """

    # ─── Config ────────────────────────────────────────────
    BUSINESS_HOURS_START = 9    # 9 AM
    BUSINESS_HOURS_END = 18     # 6 PM
    WEEKEND_DAYS = {5, 6}       # Saturday, Sunday

    BURST_WINDOW_SECONDS = 60   # نافذة البوست
    BURST_THRESHOLD = 3.0       # 3x المعدل الطبيعي

    # ─── Feature Names (للتوثيق) ──────────────────────────
    FEATURE_NAMES = [
        "hour_sin", "hour_cos",
        "day_sin", "day_cos",
        "is_weekend", "is_business_hours", "is_night",
        "mean_interval", "std_interval", "min_interval", "max_interval",
        "median_interval", "interval_range",
        "event_rate_per_sec", "event_rate_per_min",
        "burst_score", "regularity_score",
        "activity_density", "unique_hours", "unique_days",
        "session_duration_sec", "events_count",
    ]

    # ═══════════════════════════════════════════════════════
    #  Cyclical Encoding
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def cyclical_encode(
        value: float,
        period: float,
    ) -> Tuple[float, float]:
        """
        بيعمل cyclical encoding للقيم الدورية.

        مثال: 23:00 و 01:00 قريبين (مش بعيدين بـ 22 ساعة).

        Returns:
            (sin, cos)
        """
        try:
            angle = 2.0 * math.pi * value / period
            return math.sin(angle), math.cos(angle)
        except (ValueError, ZeroDivisionError):
            return 0.0, 0.0

    @classmethod
    def hour_of_day_features(
        cls,
        timestamp: float,
    ) -> Dict[str, float]:
        """
        Features من الساعة (0-23).
        """
        try:
            dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
            hour = dt.hour
            day_of_week = dt.weekday()

            hour_sin, hour_cos = cls.cyclical_encode(hour, 24.0)
            day_sin, day_cos = cls.cyclical_encode(day_of_week, 7.0)

            is_weekend = 1.0 if day_of_week in cls.WEEKEND_DAYS else 0.0
            is_business_hours = (
                1.0 if cls.BUSINESS_HOURS_START <= hour < cls.BUSINESS_HOURS_END
                else 0.0
            )
            is_night = 1.0 if (hour < 6 or hour >= 22) else 0.0

            return {
                "hour_sin": hour_sin,
                "hour_cos": hour_cos,
                "day_sin": day_sin,
                "day_cos": day_cos,
                "is_weekend": is_weekend,
                "is_business_hours": is_business_hours,
                "is_night": is_night,
                "hour": float(hour),
                "day_of_week": float(day_of_week),
            }
        except (ValueError, OSError, OverflowError):
            return {
                "hour_sin": 0.0, "hour_cos": 0.0,
                "day_sin": 0.0, "day_cos": 0.0,
                "is_weekend": 0.0, "is_business_hours": 0.0,
                "is_night": 0.0, "hour": 0.0, "day_of_week": 0.0,
            }

    # ═══════════════════════════════════════════════════════
    #  Interval Features
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def compute_intervals(timestamps: List[float]) -> List[float]:
        """بيحسب الفروق بين كل timestamp واللي بعده."""
        if not timestamps or len(timestamps) < 2:
            return []

        # رتب تصاعدي
        sorted_ts = sorted(timestamps)

        intervals = [
            sorted_ts[i + 1] - sorted_ts[i]
            for i in range(len(sorted_ts) - 1)
        ]

        # شيل القيم السالبة (لو فيه)
        return [max(0.0, iv) for iv in intervals]

    @classmethod
    def interval_features(
        cls,
        timestamps: List[float],
    ) -> Dict[str, float]:
        """
        Features من الـ intervals.
        """
        intervals = cls.compute_intervals(timestamps)

        if not intervals:
            return {
                "mean_interval": 0.0,
                "std_interval": 0.0,
                "min_interval": 0.0,
                "max_interval": 0.0,
                "median_interval": 0.0,
                "interval_range": 0.0,
            }

        arr = np.array(intervals, dtype=np.float64)

        return {
            "mean_interval": float(np.mean(arr)),
            "std_interval": float(np.std(arr)),
            "min_interval": float(np.min(arr)),
            "max_interval": float(np.max(arr)),
            "median_interval": float(np.median(arr)),
            "interval_range": float(np.max(arr) - np.min(arr)),
        }

    # ═══════════════════════════════════════════════════════
    #  Rate Features
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def rate_features(timestamps: List[float]) -> Dict[str, float]:
        """
        Features من معدل الأحداث.
        """
        if not timestamps or len(timestamps) < 2:
            return {
                "event_rate_per_sec": 0.0,
                "event_rate_per_min": 0.0,
                "events_count": float(len(timestamps)) if timestamps else 0.0,
            }

        sorted_ts = sorted(timestamps)
        duration = sorted_ts[-1] - sorted_ts[0]

        if duration <= 0:
            return {
                "event_rate_per_sec": 0.0,
                "event_rate_per_min": 0.0,
                "events_count": float(len(timestamps)),
            }

        events_count = len(timestamps)
        rate_per_sec = events_count / duration

        return {
            "event_rate_per_sec": float(rate_per_sec),
            "event_rate_per_min": float(rate_per_sec * 60.0),
            "events_count": float(events_count),
        }

    # ═══════════════════════════════════════════════════════
    #  Burst Detection
    # ═══════════════════════════════════════════════════════

    @classmethod
    def burst_score(
        cls,
        timestamps: List[float],
        window_seconds: Optional[int] = None,
    ) -> float:
        """
        بيحسب burst score.

        Burst = نشاط كثيف في نافذة قصيرة مقارنة بالمعدل الطبيعي.
        """
        window = window_seconds or cls.BURST_WINDOW_SECONDS

        if not timestamps or len(timestamps) < 3:
            return 0.0

        sorted_ts = sorted(timestamps)

        # احسب المعدل العام
        total_duration = sorted_ts[-1] - sorted_ts[0]
        if total_duration <= 0:
            return 0.0

        overall_rate = len(timestamps) / total_duration

        # احسب أعلى معدل في أي نافذة
        max_window_count = 0
        for i in range(len(sorted_ts)):
            window_end = sorted_ts[i] + window
            # عدد الأحداث في النافذة
            count = 0
            for j in range(i, len(sorted_ts)):
                if sorted_ts[j] <= window_end:
                    count += 1
                else:
                    break
            max_window_count = max(max_window_count, count)

        if max_window_count < 2:
            return 0.0

        # معدل النافذة الأقصى
        peak_rate = max_window_count / window

        # نسبة البوست
        burst_ratio = peak_rate / overall_rate if overall_rate > 0 else 0.0

        # نطبعه في نطاق منطقي (0-10)
        return float(min(burst_ratio, 10.0))

    # ═══════════════════════════════════════════════════════
    #  Regularity Score
    # ═══════════════════════════════════════════════════════

    @classmethod
    def regularity_score(cls, timestamps: List[float]) -> float:
        """
        بيحسب regularity score.

        - Regular (bot-like): الانحراف المعياري صغير
        - Random (human-like): الانحراف المعياري كبير
        """
        intervals = cls.compute_intervals(timestamps)

        if len(intervals) < 2:
            return 0.0

        arr = np.array(intervals, dtype=np.float64)
        mean = float(np.mean(arr))
        std = float(np.std(arr))

        if mean <= 0:
            return 1.0  # intervals كلها صفر → منتظم جداً

        # Coefficient of Variation
        cv = std / mean

        # حوّل لـ score (0-1):
        # cv < 0.1 → منتظم جداً → score قريب من 1
        # cv > 0.5 → عشوائي → score قريب من 0
        if cv >= 0.5:
            return 0.0
        if cv <= 0.1:
            return 1.0

        return float(1.0 - ((cv - 0.1) / 0.4))

    # ═══════════════════════════════════════════════════════
    #  Activity Density
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def activity_density(
        timestamps: List[float],
        total_window_seconds: Optional[float] = None,
    ) -> float:
        """
        بيحسب كثافة النشاط.

        كام event في كل ساعة؟
        """
        if not timestamps:
            return 0.0

        sorted_ts = sorted(timestamps)

        if total_window_seconds is None:
            total_window_seconds = (
                sorted_ts[-1] - sorted_ts[0]
                if len(sorted_ts) > 1
                else 3600.0
            )

        if total_window_seconds <= 0:
            return 0.0

        # events per hour
        return float(len(timestamps) / (total_window_seconds / 3600.0))

    # ═══════════════════════════════════════════════════════
    #  Time Distribution Features
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def time_distribution_features(
        timestamps: List[float],
    ) -> Dict[str, float]:
        """
        Features من توزيع الأحداث على الساعات والأيام.
        """
        if not timestamps:
            return {
                "unique_hours": 0.0,
                "unique_days": 0.0,
                "activity_density": 0.0,
                "session_duration_sec": 0.0,
            }

        hours = set()
        days = set()

        for ts in timestamps:
            try:
                dt = datetime.fromtimestamp(ts, tz=timezone.utc)
                hours.add(dt.hour)
                days.add(dt.date())
            except (ValueError, OSError):
                continue

        sorted_ts = sorted(timestamps)
        duration = (
            sorted_ts[-1] - sorted_ts[0]
            if len(sorted_ts) > 1
            else 0.0
        )

        return {
            "unique_hours": float(len(hours)),
            "unique_days": float(len(days)),
            "session_duration_sec": float(duration),
        }

    # ═══════════════════════════════════════════════════════
    #  Main: Extract All Features
    # ═══════════════════════════════════════════════════════

    @classmethod
    def extract(cls, timestamps: List[float]) -> Dict[str, float]:
        """
        بيستخرج كل الـ temporal features.

        Args:
            timestamps: قائمة Unix timestamps

        Returns:
            dict فيه كل الـ features
        """
        features: Dict[str, float] = {}

        if not timestamps:
            # رجع كل الـ features بـ 0
            for name in cls.FEATURE_NAMES:
                features[name] = 0.0
            return features

        # 1. أحدث timestamp (للـ hour/day features)
        latest_ts = max(timestamps)
        hour_features = cls.hour_of_day_features(latest_ts)

        # 2. Interval features
        interval_feats = cls.interval_features(timestamps)

        # 3. Rate features
        rate_feats = cls.rate_features(timestamps)

        # 4. Burst score
        burst = cls.burst_score(timestamps)

        # 5. Regularity score
        regularity = cls.regularity_score(timestamps)

        # 6. Activity density
        density = cls.activity_density(timestamps)

        # 7. Time distribution
        time_dist = cls.time_distribution_features(timestamps)

        # دمج الكل
        features.update({
            "hour_sin": hour_features["hour_sin"],
            "hour_cos": hour_features["hour_cos"],
            "day_sin": hour_features["day_sin"],
            "day_cos": hour_features["day_cos"],
            "is_weekend": hour_features["is_weekend"],
            "is_business_hours": hour_features["is_business_hours"],
            "is_night": hour_features["is_night"],

            "mean_interval": interval_feats["mean_interval"],
            "std_interval": interval_feats["std_interval"],
            "min_interval": interval_feats["min_interval"],
            "max_interval": interval_feats["max_interval"],
            "median_interval": interval_feats["median_interval"],
            "interval_range": interval_feats["interval_range"],

            "event_rate_per_sec": rate_feats["event_rate_per_sec"],
            "event_rate_per_min": rate_feats["event_rate_per_min"],

            "burst_score": burst,
            "regularity_score": regularity,
            "activity_density": density,

            "unique_hours": time_dist["unique_hours"],
            "unique_days": time_dist["unique_days"],
            "session_duration_sec": time_dist["session_duration_sec"],
            "events_count": float(len(timestamps)),
        })

        return features

    @classmethod
    def extract_as_vector(
        cls,
        timestamps: List[float],
    ) -> np.ndarray:
        """
        بيستخرج الـ features كـ numpy vector.

        مفيد للـ ML models.
        """
        features = cls.extract(timestamps)
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
    def is_bot_like(
        cls,
        timestamps: List[float],
    ) -> Dict[str, Any]:
        """
        بيحدد لو السلوك bot-like بناءً على temporal features.

        Returns:
            dict فيه: is_bot_like, confidence, reasons
        """
        if len(timestamps) < 5:
            return {
                "is_bot_like": False,
                "confidence": 0.0,
                "reasons": [],
            }

        features = cls.extract(timestamps)
        reasons = []
        score = 0.0

        # regularity عالي = bot
        if features["regularity_score"] > 0.7:
            reasons.append("high_regularity")
            score += 40

        # burst عالي = bot
        if features["burst_score"] > 3.0:
            reasons.append("high_burst")
            score += 30

        # interval صغير جداً
        if 0 < features["mean_interval"] < 1.0:
            reasons.append("very_fast_intervals")
            score += 20

        # event rate عالي
        if features["event_rate_per_min"] > 60:
            reasons.append("high_event_rate")
            score += 20

        confidence = min(score, 100)

        return {
            "is_bot_like": confidence >= 50,
            "confidence": confidence,
            "reasons": reasons,
            "features": features,
        }

    @classmethod
    def compare_patterns(
        cls,
        timestamps1: List[float],
        timestamps2: List[float],
    ) -> Dict[str, Any]:
        """
        بيقارن نمطين زمنيين.

        مفيد للـ baseline comparison.
        """
        features1 = cls.extract(timestamps1)
        features2 = cls.extract(timestamps2)

        # احسب الفروق
        common_features = [
            "hour_sin", "hour_cos", "regularity_score",
            "burst_score", "mean_interval",
        ]

        differences = {}
        total_diff = 0.0

        for name in common_features:
            v1 = features1.get(name, 0.0)
            v2 = features2.get(name, 0.0)
            diff = abs(v1 - v2)
            differences[name] = diff
            total_diff += diff

        avg_diff = total_diff / len(common_features) if common_features else 0.0

        return {
            "avg_difference": float(avg_diff),
            "is_similar": avg_diff < 0.2,
            "differences": differences,
            "features1": features1,
            "features2": features2,
        }


# ─── Standalone functions ─────────────────────────────

def extract_temporal_features(
    timestamps: List[float],
) -> Dict[str, float]:
    """Shortcut for TemporalFeatures.extract."""
    return TemporalFeatures.extract(timestamps)


def extract_as_vector(timestamps: List[float]) -> np.ndarray:
    """Shortcut for TemporalFeatures.extract_as_vector."""
    return TemporalFeatures.extract_as_vector(timestamps)


def is_bot_like(timestamps: List[float]) -> Dict[str, Any]:
    """Shortcut for TemporalFeatures.is_bot_like."""
    return TemporalFeatures.is_bot_like(timestamps)


def cyclical_encode(value: float, period: float) -> Tuple[float, float]:
    """Shortcut for TemporalFeatures.cyclical_encode."""
    return TemporalFeatures.cyclical_encode(value, period)