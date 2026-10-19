"""
Geographic Features — Geospatial feature extraction for ML models.

بيوفر:
- Distance features (haversine-based)
- Velocity features (travel speed)
- Geographic spread (centroid, dispersion)
- Impossible travel detection
- Country/continent diversity
- Location change frequency
- Geographic entropy
- Timezone shift detection
- Bearing & direction changes
- Distance from baseline

الفكرة:
- بيستخرج features من locations (lat/lon sequences)
- Features بتُستخدم من ML models للـ anomaly detection
- بيساعد في كشف:
  * Account Takeover (impossible travel)
  * VPN/Proxy switching
  * Distributed attacks from different countries

الاستخدام:
- account_takeover.py
- user_baseline.py
- session_analyzer.py
- anomaly_detection.py
- feature_extractor.py
"""

import math
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import structlog

from app.core.geo_utils import GeoUtils

logger = structlog.get_logger()


class GeographicFeatures:
    """
    Geographic Feature Extraction.

    بيستخرج features من locations (lat/lon + timestamps).
    """

    # ─── Config ────────────────────────────────────────────
    MIN_LOCATIONS = 2
    MAX_FLIGHT_SPEED_KMH = 900
    EARTH_RADIUS_KM = 6371.0

    # ─── Feature Names ────────────────────────────────────
    FEATURE_NAMES = [
        "location_count",
        "unique_countries",
        "unique_continents",
        "total_distance_km",
        "avg_distance_km",
        "max_distance_km",
        "min_distance_km",
        "distance_std",
        "avg_speed_kmh",
        "max_speed_kmh",
        "impossible_travel_count",
        "impossible_travel_ratio",
        "country_diversity",
        "continent_diversity",
        "geographic_entropy",
        "centroid_lat",
        "centroid_lon",
        "avg_distance_from_centroid",
        "max_distance_from_centroid",
        "location_change_rate",
        "timezone_shift_score",
    ]

    # ═══════════════════════════════════════════════════════
    #  Distance Features
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def _extract_coords(
        locations: List[Dict[str, Any]],
    ) -> List[Tuple[float, float]]:
        """بيستخرج lat/lon pairs من locations."""
        coords = []
        for loc in locations:
            if not isinstance(loc, dict):
                continue

            lat = loc.get("lat") or loc.get("latitude")
            lon = loc.get("lon") or loc.get("lng") or loc.get("longitude")

            if GeoUtils.is_valid_coords(lat, lon):
                coords.append((float(lat), float(lon)))

        return coords

    @staticmethod
    def _extract_timestamps(
        locations: List[Dict[str, Any]],
    ) -> List[float]:
        """بيستخرج timestamps من locations."""
        timestamps = []
        for loc in locations:
            if not isinstance(loc, dict):
                continue
            ts = loc.get("timestamp") or loc.get("time")
            if ts is not None:
                try:
                    timestamps.append(float(ts))
                except (ValueError, TypeError):
                    continue
        return timestamps

    @classmethod
    def pairwise_distances(
        cls,
        locations: List[Dict[str, Any]],
    ) -> List[float]:
        """
        بيحسب المسافات بين كل location واللي بعده.
        """
        coords = cls._extract_coords(locations)

        if len(coords) < 2:
            return []

        distances = []
        for i in range(len(coords) - 1):
            d = GeoUtils.haversine_distance(
                coords[i][0], coords[i][1],
                coords[i + 1][0], coords[i + 1][1],
            )
            if d is not None:
                distances.append(d)

        return distances

    @classmethod
    def total_distance(cls, locations: List[Dict[str, Any]]) -> float:
        """مجموع المسافات."""
        distances = cls.pairwise_distances(locations)
        return float(sum(distances)) if distances else 0.0

    @classmethod
    def distance_stats(
        cls,
        locations: List[Dict[str, Any]],
    ) -> Dict[str, float]:
        """إحصائيات المسافات."""
        distances = cls.pairwise_distances(locations)

        if not distances:
            return {
                "total": 0.0,
                "avg": 0.0,
                "max": 0.0,
                "min": 0.0,
                "std": 0.0,
            }

        arr = np.array(distances, dtype=np.float64)

        return {
            "total": float(np.sum(arr)),
            "avg": float(np.mean(arr)),
            "max": float(np.max(arr)),
            "min": float(np.min(arr)),
            "std": float(np.std(arr)),
        }

    # ═══════════════════════════════════════════════════════
    #  Velocity Features
    # ═══════════════════════════════════════════════════════

    @classmethod
    def velocity_stats(
        cls,
        locations: List[Dict[str, Any]],
    ) -> Dict[str, float]:
        """
        إحصائيات السرعة (km/h).

        Returns:
            dict فيه: avg, max, count
        """
        coords = cls._extract_coords(locations)
        timestamps = cls._extract_timestamps(locations)

        # لازم نفس العدد
        min_len = min(len(coords), len(timestamps))
        if min_len < 2:
            return {"avg": 0.0, "max": 0.0, "count": 0.0}

        coords = coords[:min_len]
        timestamps = timestamps[:min_len]

        speeds = []
        for i in range(min_len - 1):
            time_diff = timestamps[i + 1] - timestamps[i]
            if time_diff <= 0:
                continue

            distance = GeoUtils.haversine_distance(
                coords[i][0], coords[i][1],
                coords[i + 1][0], coords[i + 1][1],
            )
            if distance is None:
                continue

            speed_kmh = distance / (time_diff / 3600.0)
            speeds.append(speed_kmh)

        if not speeds:
            return {"avg": 0.0, "max": 0.0, "count": 0.0}

        return {
            "avg": float(np.mean(speeds)),
            "max": float(np.max(speeds)),
            "count": float(len(speeds)),
        }

    # ═══════════════════════════════════════════════════════
    #  Impossible Travel
    # ═══════════════════════════════════════════════════════

    @classmethod
    def impossible_travel_stats(
        cls,
        locations: List[Dict[str, Any]],
    ) -> Dict[str, float]:
        """
        إحصائيات الرحلات المستحيلة.

        Returns:
            dict فيه: count, ratio
        """
        coords = cls._extract_coords(locations)
        timestamps = cls._extract_timestamps(locations)

        min_len = min(len(coords), len(timestamps))
        if min_len < 2:
            return {"count": 0.0, "ratio": 0.0}

        coords = coords[:min_len]
        timestamps = timestamps[:min_len]

        impossible_count = 0
        total_transitions = 0

        for i in range(min_len - 1):
            time_diff = timestamps[i + 1] - timestamps[i]
            total_transitions += 1

            is_impossible, _ = GeoUtils.is_impossible_travel(
                coords[i][0], coords[i][1],
                coords[i + 1][0], coords[i + 1][1],
                time_diff,
                max_speed_kmh=cls.MAX_FLIGHT_SPEED_KMH,
            )

            if is_impossible:
                impossible_count += 1

        ratio = impossible_count / total_transitions if total_transitions > 0 else 0.0

        return {
            "count": float(impossible_count),
            "ratio": float(ratio),
        }

    # ═══════════════════════════════════════════════════════
    #  Country / Continent Diversity
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def _extract_countries(
        locations: List[Dict[str, Any]],
    ) -> List[str]:
        """بيستخرج countries من locations."""
        countries = []
        for loc in locations:
            if not isinstance(loc, dict):
                continue
            country = loc.get("country") or loc.get("country_code")
            if country:
                countries.append(str(country).upper().strip())
        return countries

    @classmethod
    def country_stats(
        cls,
        locations: List[Dict[str, Any]],
    ) -> Dict[str, float]:
        """
        إحصائيات الدول.

        Returns:
            dict فيه: unique_count, diversity, entropy
        """
        countries = cls._extract_countries(locations)

        if not countries:
            return {
                "unique_count": 0.0,
                "diversity": 0.0,
                "entropy": 0.0,
            }

        unique = set(countries)
        unique_count = len(unique)
        diversity = unique_count / len(countries)

        # احسب entropy
        counter = Counter(countries)
        total = len(countries)
        entropy = 0.0
        for count in counter.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)

        return {
            "unique_count": float(unique_count),
            "diversity": float(diversity),
            "entropy": float(entropy),
        }

    @classmethod
    def continent_stats(
        cls,
        locations: List[Dict[str, Any]],
    ) -> Dict[str, float]:
        """إحصائيات القارات."""
        countries = cls._extract_countries(locations)

        if not countries:
            return {"unique_count": 0.0, "diversity": 0.0}

        continents = set()
        for country in countries:
            cont = GeoUtils.get_continent(country)
            if cont:
                continents.add(cont)

        unique_count = len(continents)
        diversity = unique_count / len(countries)

        return {
            "unique_count": float(unique_count),
            "diversity": float(diversity),
        }

    # ═══════════════════════════════════════════════════════
    #  Geographic Centroid & Spread
    # ═══════════════════════════════════════════════════════

    @classmethod
    def centroid_features(
        cls,
        locations: List[Dict[str, Any]],
    ) -> Dict[str, float]:
        """
        centroid + spread.
        """
        coords = cls._extract_coords(locations)

        if not coords:
            return {
                "centroid_lat": 0.0,
                "centroid_lon": 0.0,
                "avg_distance_from_centroid": 0.0,
                "max_distance_from_centroid": 0.0,
            }

        # centroid
        avg_lat = sum(c[0] for c in coords) / len(coords)
        avg_lon = sum(c[1] for c in coords) / len(coords)

        # distances from centroid
        distances = []
        for lat, lon in coords:
            d = GeoUtils.haversine_distance(avg_lat, avg_lon, lat, lon)
            if d is not None:
                distances.append(d)

        if not distances:
            return {
                "centroid_lat": round(avg_lat, 4),
                "centroid_lon": round(avg_lon, 4),
                "avg_distance_from_centroid": 0.0,
                "max_distance_from_centroid": 0.0,
            }

        return {
            "centroid_lat": round(avg_lat, 4),
            "centroid_lon": round(avg_lon, 4),
            "avg_distance_from_centroid": float(np.mean(distances)),
            "max_distance_from_centroid": float(np.max(distances)),
        }

    # ═══════════════════════════════════════════════════════
    #  Location Change Rate
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def location_change_rate(
        locations: List[Dict[str, Any]],
    ) -> float:
        """
        عدد مرات تغيير الموقع / إجمالي الوقت (ساعة).

        Returns:
            changes per hour
        """
        timestamps = []
        for loc in locations:
            if not isinstance(loc, dict):
                continue
            ts = loc.get("timestamp") or loc.get("time")
            if ts is not None:
                try:
                    timestamps.append(float(ts))
                except (ValueError, TypeError):
                    continue

        if len(timestamps) < 2:
            return 0.0

        sorted_ts = sorted(timestamps)
        duration = sorted_ts[-1] - sorted_ts[0]

        if duration <= 0:
            return 0.0

        changes = len(locations) - 1
        duration_hours = duration / 3600.0

        return float(changes / duration_hours) if duration_hours > 0 else 0.0

    # ═══════════════════════════════════════════════════════
    #  Timezone Shift
    # ═══════════════════════════════════════════════════════

    @classmethod
    def timezone_shift_score(
        cls,
        locations: List[Dict[str, Any]],
    ) -> float:
        """
        بيكشف تغييرات timezone الكبيرة.

        Returns:
            score (0-1) — أعلى = shifts أكبر
        """
        countries = cls._extract_countries(locations)

        if len(countries) < 2:
            return 0.0

        # احسب فروق timezone بين كل زوج متتالي
        shifts = []
        for i in range(len(countries) - 1):
            tz1 = GeoUtils.get_timezone_offset(countries[i])
            tz2 = GeoUtils.get_timezone_offset(countries[i + 1])

            if tz1 is not None and tz2 is not None:
                shift = abs(tz2 - tz1)
                shifts.append(shift)

        if not shifts:
            return 0.0

        # max shift ممكن = 26 ساعة (من -12 لـ +14)
        max_shift = 26.0
        avg_shift = float(np.mean(shifts))

        return float(min(avg_shift / max_shift, 1.0))

    # ═══════════════════════════════════════════════════════
    #  Main: Extract All Features
    # ═══════════════════════════════════════════════════════

    @classmethod
    def extract(
        cls,
        locations: List[Dict[str, Any]],
    ) -> Dict[str, float]:
        """
        بيستخرج كل الـ geographic features.

        Args:
            locations: قائمة locations، كل location فيه:
                - lat/latitude
                - lon/lng/longitude
                - timestamp
                - country/country_code (اختياري)

        Returns:
            dict فيه كل الـ features
        """
        features: Dict[str, float] = {}

        if not locations or len(locations) < cls.MIN_LOCATIONS:
            for name in cls.FEATURE_NAMES:
                features[name] = 0.0
            return features

        # 1. Location count
        location_count = float(len(locations))

        # 2. Country stats
        country_stats = cls.country_stats(locations)

        # 3. Continent stats
        continent_stats = cls.continent_stats(locations)

        # 4. Distance stats
        distance_stats = cls.distance_stats(locations)

        # 5. Velocity stats
        velocity_stats = cls.velocity_stats(locations)

        # 6. Impossible travel
        impossible = cls.impossible_travel_stats(locations)

        # 7. Centroid
        centroid = cls.centroid_features(locations)

        # 8. Change rate
        change_rate = cls.location_change_rate(locations)

        # 9. Timezone shift
        tz_shift = cls.timezone_shift_score(locations)

        features.update({
            "location_count": location_count,

            "unique_countries": country_stats["unique_count"],
            "unique_continents": continent_stats["unique_count"],
            "country_diversity": country_stats["diversity"],
            "continent_diversity": continent_stats["diversity"],
            "geographic_entropy": country_stats["entropy"],

            "total_distance_km": distance_stats["total"],
            "avg_distance_km": distance_stats["avg"],
            "max_distance_km": distance_stats["max"],
            "min_distance_km": distance_stats["min"],
            "distance_std": distance_stats["std"],

            "avg_speed_kmh": velocity_stats["avg"],
            "max_speed_kmh": velocity_stats["max"],

            "impossible_travel_count": impossible["count"],
            "impossible_travel_ratio": impossible["ratio"],

            "centroid_lat": centroid["centroid_lat"],
            "centroid_lon": centroid["centroid_lon"],
            "avg_distance_from_centroid": centroid["avg_distance_from_centroid"],
            "max_distance_from_centroid": centroid["max_distance_from_centroid"],

            "location_change_rate": change_rate,
            "timezone_shift_score": tz_shift,
        })

        return features

    @classmethod
    def extract_as_vector(
        cls,
        locations: List[Dict[str, Any]],
    ) -> np.ndarray:
        """بيستخرج الـ features كـ numpy vector."""
        features = cls.extract(locations)
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
    def is_suspicious_geography(
        cls,
        locations: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        بيحدد لو الـ geographic pattern مشبوه.

        Returns:
            dict فيه: is_suspicious, confidence, reasons
        """
        if not locations or len(locations) < cls.MIN_LOCATIONS:
            return {
                "is_suspicious": False,
                "confidence": 0.0,
                "reasons": [],
            }

        features = cls.extract(locations)
        reasons = []
        score = 0.0

        # 1. Impossible travel
        if features["impossible_travel_ratio"] > 0.2:
            reasons.append("impossible_travel")
            score += 40
        elif features["impossible_travel_ratio"] > 0.1:
            reasons.append("some_impossible_travel")
            score += 20

        # 2. Multiple countries في وقت قصير
        if (
            features["unique_countries"] >= 3
            and features["location_change_rate"] > 0.5
        ):
            reasons.append("rapid_country_changes")
            score += 30

        # 3. Multiple continents
        if features["unique_continents"] >= 2:
            reasons.append("multi_continent")
            score += 25

        # 4. High timezone shift
        if features["timezone_shift_score"] > 0.2:
            reasons.append("large_timezone_shifts")
            score += 20

        # 5. High speed
        if features["max_speed_kmh"] > cls.MAX_FLIGHT_SPEED_KMH:
            reasons.append("superhuman_speed")
            score += 30

        # 6. High geographic entropy (نشاط من أماكن كتير)
        if features["geographic_entropy"] > 1.5:
            reasons.append("high_geographic_entropy")
            score += 15

        confidence = min(score, 100)

        return {
            "is_suspicious": confidence >= 50,
            "confidence": confidence,
            "reasons": reasons,
            "features": features,
        }

    @classmethod
    def detect_vpn_switching(
        cls,
        locations: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        بيكشف نمط VPN switching.

        VPN switching = تغييرات سريعة بين دول مختلفة
        بدون impossible travel (لأن المستخدم ثابت).

        Returns:
            dict فيه: is_vpn_switching, confidence
        """
        if not locations or len(locations) < 2:
            return {
                "is_vpn_switching": False,
                "confidence": 0.0,
            }

        features = cls.extract(locations)
        score = 0.0

        # 1. multiple countries
        if features["unique_countries"] >= 3:
            score += 30
        elif features["unique_countries"] >= 2:
            score += 15

        # 2. high change rate
        if features["location_change_rate"] > 1.0:
            score += 30

        # 3. low avg speed (المستخدم نفسه بيبدل locations)
        if 0 < features["avg_speed_kmh"] < 500:
            score += 20

        # 4. high geographic entropy
        if features["geographic_entropy"] > 1.0:
            score += 20

        confidence = min(score, 100)

        return {
            "is_vpn_switching": confidence >= 50,
            "confidence": confidence,
            "features": features,
        }


# ─── Standalone functions ─────────────────────────────

def extract_geographic_features(
    locations: List[Dict[str, Any]],
) -> Dict[str, float]:
    """Shortcut for GeographicFeatures.extract."""
    return GeographicFeatures.extract(locations)


def is_suspicious_geography(
    locations: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Shortcut for GeographicFeatures.is_suspicious_geography."""
    return GeographicFeatures.is_suspicious_geography(locations)


def total_distance(locations: List[Dict[str, Any]]) -> float:
    """Shortcut for GeographicFeatures.total_distance."""
    return GeographicFeatures.total_distance(locations)


def velocity_stats(
    locations: List[Dict[str, Any]],
) -> Dict[str, float]:
    """Shortcut for GeographicFeatures.velocity_stats."""
    return GeographicFeatures.velocity_stats(locations)