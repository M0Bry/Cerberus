"""
Geo Utils — Shared geographic utilities.

بيوفر:
- Haversine distance
- Bounding box checks
- Country/continent lookups
- Country coordinates
- Country code validation
- Timezone estimation from coordinates
- Distance-based clustering
- Impossible travel detection helper
- IP geolocation result parsing

الفكرة:
- مكتبة مساعدة بتُستخدم من كل ملفات Tier 2
- بسيطة، سريعة، بدون dependencies خارجية
- error-safe (بترجع None/False بدل ما ترمي exception)

الاستخدام:
- account_takeover.py (impossible travel)
- geoip.py
- geographic_features.py
- ip_reputation.py
- أي ملف محتاج geographic calculations
"""

import math
from typing import Any, Dict, List, Optional, Tuple

import structlog

logger = structlog.get_logger()


class GeoUtils:
    """
    Geographic Utilities.

    كل الدوال بترجع None/False لو فشلت بدل ما ترمي exception.
    """

    # ─── Config ────────────────────────────────────────────
    EARTH_RADIUS_KM = 6371.0
    MAX_FLIGHT_SPEED_KMH = 900     # سرعة الطيران التجاري
    MAX_LAND_SPEED_KMH = 150       # سرعة السيارة القصوى

    # ─── Country Coordinates (Country Centroids) ──────────
    # إحداثيات تقريبية لمركز كل دولة
    COUNTRY_COORDS: Dict[str, Tuple[float, float]] = {
        "US": (37.0902, -95.7129),
        "CA": (56.1304, -106.3468),
        "MX": (23.6345, -102.5528),
        "BR": (-14.2350, -51.9253),
        "AR": (-38.4161, -63.6167),
        "GB": (55.3781, -3.4360),
        "FR": (46.2276, 2.2137),
        "DE": (51.1657, 10.4515),
        "IT": (41.8719, 12.5674),
        "ES": (40.4637, -3.7492),
        "NL": (52.1326, 5.2913),
        "BE": (50.5039, 4.4699),
        "CH": (46.8182, 8.2275),
        "AT": (47.5162, 14.5501),
        "SE": (60.1282, 18.6435),
        "NO": (60.4720, 8.4689),
        "DK": (56.2639, 9.5018),
        "FI": (61.9241, 25.7482),
        "PL": (51.9194, 19.1451),
        "RU": (61.5240, 105.3188),
        "UA": (48.3794, 31.1656),
        "TR": (38.9637, 35.2433),
        "EG": (26.8206, 30.8025),
        "SA": (23.8859, 45.0792),
        "AE": (23.4241, 53.8478),
        "IL": (31.0461, 34.8516),
        "IR": (32.4279, 53.6880),
        "IQ": (33.2232, 43.6793),
        "SY": (34.8021, 38.9968),
        "JO": (30.5852, 36.2384),
        "LB": (33.8547, 35.8623),
        "KW": (29.3117, 47.4818),
        "QA": (25.3548, 51.1839),
        "BH": (26.0667, 50.5577),
        "OM": (21.4735, 55.9754),
        "YE": (15.5527, 48.5164),
        "SD": (12.8628, 30.2176),
        "LY": (26.3351, 17.2283),
        "TN": (33.8869, 9.5375),
        "DZ": (28.0339, 1.6596),
        "MA": (31.7917, -7.0926),
        "NG": (9.0820, 8.6753),
        "KE": (-0.0236, 37.9062),
        "ZA": (-30.5595, 22.9375),
        "ET": (9.1450, 40.4897),
        "GH": (7.9465, -1.0232),
        "CN": (35.8617, 104.1954),
        "JP": (36.2048, 138.2529),
        "KR": (35.9078, 127.7669),
        "IN": (20.5937, 78.9629),
        "PK": (30.3753, 69.3451),
        "BD": (23.6850, 90.3563),
        "ID": (-0.7893, 113.9213),
        "PH": (12.8797, 121.7740),
        "TH": (15.8700, 100.9925),
        "VN": (14.0583, 108.2772),
        "MY": (4.2105, 101.9758),
        "SG": (1.3521, 103.8198),
        "AU": (-25.2744, 133.7751),
        "NZ": (-40.9006, 174.8860),
    }

    # ─── Continent Mapping ────────────────────────────────
    CONTINENTS: Dict[str, List[str]] = {
        "africa": [
            "EG", "NG", "KE", "ZA", "ET", "GH", "MA", "DZ",
            "TN", "LY", "SD", "ZA",
        ],
        "asia": [
            "CN", "JP", "KR", "IN", "PK", "BD", "ID", "PH",
            "TH", "VN", "MY", "SG", "IR", "IQ", "SY", "JO",
            "LB", "KW", "QA", "BH", "OM", "YE", "SA", "AE",
            "IL", "TR",
        ],
        "europe": [
            "GB", "FR", "DE", "IT", "ES", "NL", "BE", "CH",
            "AT", "SE", "NO", "DK", "FI", "PL", "RU", "UA",
        ],
        "north_america": ["US", "CA", "MX"],
        "south_america": ["BR", "AR"],
        "oceania": ["AU", "NZ"],
    }

    # ─── Timezone Offsets (approximate, by country) ───────
    COUNTRY_TIMEZONES: Dict[str, int] = {
        "US": -5,    # EST (تقريبي)
        "CA": -5,
        "MX": -6,
        "BR": -3,
        "AR": -3,
        "GB": 0,
        "FR": 1,
        "DE": 1,
        "IT": 1,
        "ES": 1,
        "NL": 1,
        "BE": 1,
        "CH": 1,
        "AT": 1,
        "SE": 1,
        "NO": 1,
        "DK": 1,
        "FI": 2,
        "PL": 1,
        "RU": 3,
        "UA": 2,
        "TR": 3,
        "EG": 2,
        "SA": 3,
        "AE": 4,
        "IL": 2,
        "IR": 3,
        "IQ": 3,
        "SY": 3,
        "JO": 3,
        "LB": 3,
        "KW": 3,
        "QA": 3,
        "BH": 3,
        "OM": 4,
        "YE": 3,
        "SD": 2,
        "LY": 2,
        "TN": 1,
        "DZ": 1,
        "MA": 0,
        "NG": 1,
        "KE": 3,
        "ZA": 2,
        "ET": 3,
        "GH": 0,
        "CN": 8,
        "JP": 9,
        "KR": 9,
        "IN": 5,
        "PK": 5,
        "BD": 6,
        "ID": 7,
        "PH": 8,
        "TH": 7,
        "VN": 7,
        "MY": 8,
        "SG": 8,
        "AU": 10,
        "NZ": 12,
    }

    # ═══════════════════════════════════════════════════════
    #  Coordinates Validation
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def is_valid_latitude(lat: Any) -> bool:
        """بيتحقق لو latitude صحيح (-90 إلى 90)."""
        try:
            value = float(lat)
            return -90.0 <= value <= 90.0
        except (ValueError, TypeError):
            return False

    @staticmethod
    def is_valid_longitude(lon: Any) -> bool:
        """بيتحقق لو longitude صحيح (-180 إلى 180)."""
        try:
            value = float(lon)
            return -180.0 <= value <= 180.0
        except (ValueError, TypeError):
            return False

    @classmethod
    def is_valid_coords(cls, lat: Any, lon: Any) -> bool:
        """بيتحقق لو الإحداثيات صحيحة."""
        return cls.is_valid_latitude(lat) and cls.is_valid_longitude(lon)

    # ═══════════════════════════════════════════════════════
    #  Distance Calculations
    # ═══════════════════════════════════════════════════════

    @classmethod
    def haversine_distance(
        cls,
        lat1: float,
        lon1: float,
        lat2: float,
        lon2: float,
    ) -> Optional[float]:
        """
        بيحسب المسافة بين نقطتين على سطح الأرض (كم).

        Haversine Formula.
        """
        if not cls.is_valid_coords(lat1, lon1):
            return None
        if not cls.is_valid_coords(lat2, lon2):
            return None

        try:
            lat1_rad = math.radians(float(lat1))
            lat2_rad = math.radians(float(lat2))
            delta_lat = math.radians(float(lat2) - float(lat1))
            delta_lon = math.radians(float(lon2) - float(lon1))

            a = (
                math.sin(delta_lat / 2) ** 2
                + math.cos(lat1_rad) * math.cos(lat2_rad)
                * math.sin(delta_lon / 2) ** 2
            )
            c = 2 * math.asin(math.sqrt(a))

            return cls.EARTH_RADIUS_KM * c
        except (ValueError, TypeError) as e:
            logger.debug("haversine_failed", error=str(e))
            return None

    @classmethod
    def distance_between_countries(
        cls,
        country1: str,
        country2: str,
    ) -> Optional[float]:
        """بيحسب المسافة بين دولتين (كم)."""
        if not country1 or not country2:
            return None

        c1 = country1.upper().strip()
        c2 = country2.upper().strip()

        if c1 == c2:
            return 0.0

        coords1 = cls.COUNTRY_COORDS.get(c1)
        coords2 = cls.COUNTRY_COORDS.get(c2)

        if not coords1 or not coords2:
            return None

        return cls.haversine_distance(
            coords1[0], coords1[1],
            coords2[0], coords2[1],
        )

    @classmethod
    def calculate_speed(
        cls,
        lat1: float,
        lon1: float,
        lat2: float,
        lon2: float,
        time_diff_seconds: float,
    ) -> Optional[float]:
        """
        بيحسب السرعة المطلوبة للتنقل بين نقطتين (كم/ساعة).
        """
        if time_diff_seconds <= 0:
            return None

        distance = cls.haversine_distance(lat1, lon1, lat2, lon2)
        if distance is None:
            return None

        time_hours = time_diff_seconds / 3600.0
        if time_hours <= 0:
            return None

        return distance / time_hours

    # ═══════════════════════════════════════════════════════
    #  Impossible Travel Detection
    # ═══════════════════════════════════════════════════════

    @classmethod
    def is_impossible_travel(
        cls,
        lat1: float,
        lon1: float,
        lat2: float,
        lon2: float,
        time_diff_seconds: float,
        max_speed_kmh: Optional[float] = None,
    ) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        بيكشف لو التنقل مستحيل.

        Returns:
            (is_impossible, details)
        """
        max_speed = max_speed_kmh or cls.MAX_FLIGHT_SPEED_KMH

        if time_diff_seconds <= 0:
            return True, {
                "reason": "invalid_time",
                "time_diff_seconds": time_diff_seconds,
            }

        distance = cls.haversine_distance(lat1, lon1, lat2, lon2)
        if distance is None:
            return False, None

        required_speed = cls.calculate_speed(
            lat1, lon1, lat2, lon2, time_diff_seconds
        )

        if required_speed is None:
            return False, None

        is_impossible = required_speed > max_speed

        details = {
            "distance_km": round(distance, 2),
            "time_hours": round(time_diff_seconds / 3600, 3),
            "required_speed_kmh": round(required_speed, 2),
            "max_speed_kmh": max_speed,
            "is_impossible": is_impossible,
        }

        return is_impossible, details

    # ═══════════════════════════════════════════════════════
    #  Bounding Box
    # ═══════════════════════════════════════════════════════

    @classmethod
    def is_in_bounding_box(
        cls,
        lat: float,
        lon: float,
        min_lat: float,
        min_lon: float,
        max_lat: float,
        max_lon: float,
    ) -> bool:
        """بيتحقق لو النقطة جوه bounding box."""
        if not cls.is_valid_coords(lat, lon):
            return False
        try:
            return (
                min_lat <= float(lat) <= max_lat
                and min_lon <= float(lon) <= max_lon
            )
        except (ValueError, TypeError):
            return False

    @classmethod
    def is_near_point(
        cls,
        lat: float,
        lon: float,
        center_lat: float,
        center_lon: float,
        radius_km: float,
    ) -> bool:
        """بيتحقق لو النقطة جوه دائرة حول نقطة تانية."""
        distance = cls.haversine_distance(lat, lon, center_lat, center_lon)
        if distance is None:
            return False
        return distance <= radius_km

    # ═══════════════════════════════════════════════════════
    #  Country Lookups
    # ═══════════════════════════════════════════════════════

    @classmethod
    def get_country_coords(
        cls,
        country_code: str,
    ) -> Optional[Tuple[float, float]]:
        """بيرجع إحداثيات الدولة."""
        if not country_code:
            return None
        return cls.COUNTRY_COORDS.get(country_code.upper().strip())

    @classmethod
    def is_valid_country_code(cls, code: str) -> bool:
        """بيتحقق لو كود الدولة صحيح."""
        if not code or not isinstance(code, str):
            return False
        return code.upper().strip() in cls.COUNTRY_COORDS

    @classmethod
    def get_continent(cls, country_code: str) -> Optional[str]:
        """بيرجع القارة من كود الدولة."""
        if not country_code:
            return None

        code = country_code.upper().strip()
        for continent, countries in cls.CONTINENTS.items():
            if code in countries:
                return continent

        return None

    @classmethod
    def get_timezone_offset(cls, country_code: str) -> Optional[int]:
        """
        بيرجع فرق التوقيت التقريبي (بالساعات).

        ملاحظة: ده تقريبي جداً — للاستخدام في الكشف فقط.
        """
        if not country_code:
            return None
        return cls.COUNTRY_TIMEZONES.get(country_code.upper().strip())

    @classmethod
    def estimate_local_hour(
        cls,
        country_code: str,
        utc_hour: int,
    ) -> Optional[int]:
        """بيحول ساعة UTC لساعة محلية تقريبية."""
        offset = cls.get_timezone_offset(country_code)
        if offset is None:
            return None
        return (utc_hour + offset) % 24

    @classmethod
    def is_same_country(cls, c1: str, c2: str) -> bool:
        """بيتحقق لو نفس الدولة."""
        if not c1 or not c2:
            return False
        return c1.upper().strip() == c2.upper().strip()

    @classmethod
    def is_same_continent(cls, c1: str, c2: str) -> bool:
        """بيتحقق لو نفس القارة."""
        continent1 = cls.get_continent(c1)
        continent2 = cls.get_continent(c2)

        if not continent1 or not continent2:
            return False

        return continent1 == continent2

    # ═══════════════════════════════════════════════════════
    #  Clustering
    # ═══════════════════════════════════════════════════════

    @classmethod
    def find_nearby_points(
        cls,
        target_lat: float,
        target_lon: float,
        points: List[Tuple[float, float]],
        radius_km: float,
    ) -> List[int]:
        """
        بيرجع indices النقاط القريبة من target.

        Args:
            target_lat, target_lon: النقطة المستهدفة
            points: قائمة نقاط (lat, lon)
            radius_km: نصف القطر

        Returns:
            قائمة indices
        """
        nearby = []
        for i, (lat, lon) in enumerate(points):
            distance = cls.haversine_distance(
                target_lat, target_lon, lat, lon
            )
            if distance is not None and distance <= radius_km:
                nearby.append(i)
        return nearby

    @classmethod
    def geographic_spread(
        cls,
        points: List[Tuple[float, float]],
    ) -> Optional[Dict[str, float]]:
        """
        بيحسب الانتشار الجغرافي لمجموعة نقاط.

        Returns:
            dict فيه: max_distance, avg_distance, centroid
        """
        if not points or len(points) < 2:
            return None

        valid_points = [
            (float(lat), float(lon))
            for lat, lon in points
            if cls.is_valid_coords(lat, lon)
        ]

        if len(valid_points) < 2:
            return None

        # احسب centroid
        avg_lat = sum(p[0] for p in valid_points) / len(valid_points)
        avg_lon = sum(p[1] for p in valid_points) / len(valid_points)

        # احسب المسافات
        distances = []
        for lat, lon in valid_points:
            d = cls.haversine_distance(avg_lat, avg_lon, lat, lon)
            if d is not None:
                distances.append(d)

        if not distances:
            return None

        # max distance بين أي نقطتين
        max_pair_distance = 0.0
        for i in range(len(valid_points)):
            for j in range(i + 1, len(valid_points)):
                d = cls.haversine_distance(
                    valid_points[i][0], valid_points[i][1],
                    valid_points[j][0], valid_points[j][1],
                )
                if d is not None and d > max_pair_distance:
                    max_pair_distance = d

        return {
            "centroid_lat": round(avg_lat, 4),
            "centroid_lon": round(avg_lon, 4),
            "max_pair_distance_km": round(max_pair_distance, 2),
            "avg_distance_from_centroid_km": round(
                sum(distances) / len(distances), 2
            ),
            "point_count": len(valid_points),
        }

    # ═══════════════════════════════════════════════════════
    #  IP Geolocation Parsing
    # ═══════════════════════════════════════════════════════

    @classmethod
    def parse_geoip_result(
        cls,
        geoip_data: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """
        بيطبع نتيجة GeoIP لشكل موحد.

        بيدعم صيغ مختلفة (MaxMind, ipapi, ipinfo, ...).
        """
        if not geoip_data:
            return None

        try:
            # جرب صيغ مختلفة للـ latitude
            lat = (
                geoip_data.get("latitude")
                or geoip_data.get("lat")
                or (geoip_data.get("location") or {}).get("lat")
            )

            # جرب صيغ مختلفة للـ longitude
            lon = (
                geoip_data.get("longitude")
                or geoip_data.get("lon")
                or geoip_data.get("lng")
                or (geoip_data.get("location") or {}).get("lng")
            )

            # تعامل مع country لو كانت dict
            country_raw = (
                geoip_data.get("country_code")
                or geoip_data.get("country")
            )

            if isinstance(country_raw, dict):
                country = (
                    country_raw.get("iso_code")
                    or country_raw.get("code")
                    or country_raw.get("iso")
                )
            else:
                country = country_raw

            city = geoip_data.get("city")

            return {
                "latitude": float(lat) if lat is not None else None,
                "longitude": float(lon) if lon is not None else None,
                "country_code": (
                    str(country).upper() if country else None
                ),
                "city": city,
                "is_valid": cls.is_valid_coords(lat, lon),
            }
        except (ValueError, TypeError, AttributeError):
            return None

    # ═══════════════════════════════════════════════════════
    #  High-Level Helpers
    # ═══════════════════════════════════════════════════════

    @classmethod
    def analyze_location_change(
        cls,
        from_country: str,
        to_country: str,
        time_diff_seconds: float,
    ) -> Dict[str, Any]:
        """
        تحليل شامل لتغيير الموقع (للـ ATO detection).

        Returns:
            dict فيه: distance_km, required_speed, is_impossible, ...
        """
        if not from_country or not to_country:
            return {
                "valid": False,
                "reason": "missing_country",
            }

        if cls.is_same_country(from_country, to_country):
            return {
                "valid": True,
                "same_country": True,
                "distance_km": 0.0,
                "is_impossible": False,
            }

        distance = cls.distance_between_countries(from_country, to_country)

        if distance is None:
            return {
                "valid": False,
                "reason": "unknown_country",
                "from_country": from_country,
                "to_country": to_country,
            }

        if time_diff_seconds <= 0:
            return {
                "valid": True,
                "distance_km": round(distance, 2),
                "same_country": False,
                "same_continent": cls.is_same_continent(
                    from_country, to_country
                ),
                "is_impossible": True,
                "reason": "invalid_time",
            }

        coords1 = cls.get_country_coords(from_country)
        coords2 = cls.get_country_coords(to_country)

        is_impossible, details = cls.is_impossible_travel(
            coords1[0], coords1[1],
            coords2[0], coords2[1],
            time_diff_seconds,
        )

        return {
            "valid": True,
            "same_country": False,
            "same_continent": cls.is_same_continent(
                from_country, to_country
            ),
            "from_country": from_country.upper(),
            "to_country": to_country.upper(),
            "distance_km": round(distance, 2),
            "is_impossible": is_impossible,
            "details": details,
        }


# ─── Standalone functions (للـ convenience) ─────────────

def haversine_distance(
    lat1: float,
    lon1: float,
    lat2: float,
    lon2: float,
) -> Optional[float]:
    """Shortcut for GeoUtils.haversine_distance."""
    return GeoUtils.haversine_distance(lat1, lon1, lat2, lon2)


def distance_between_countries(
    c1: str,
    c2: str,
) -> Optional[float]:
    """Shortcut for GeoUtils.distance_between_countries."""
    return GeoUtils.distance_between_countries(c1, c2)


def is_impossible_travel(
    lat1: float,
    lon1: float,
    lat2: float,
    lon2: float,
    time_diff_seconds: float,
) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """Shortcut for GeoUtils.is_impossible_travel."""
    return GeoUtils.is_impossible_travel(
        lat1, lon1, lat2, lon2, time_diff_seconds
    )


def get_continent(country_code: str) -> Optional[str]:
    """Shortcut for GeoUtils.get_continent."""
    return GeoUtils.get_continent(country_code)


def get_country_coords(code: str) -> Optional[Tuple[float, float]]:
    """Shortcut for GeoUtils.get_country_coords."""
    return GeoUtils.get_country_coords(code)


def is_valid_country_code(code: str) -> bool:
    """Shortcut for GeoUtils.is_valid_country_code."""
    return GeoUtils.is_valid_country_code(code)


def is_same_continent(c1: str, c2: str) -> bool:
    """Shortcut for GeoUtils.is_same_continent."""
    return GeoUtils.is_same_continent(c1, c2)


def analyze_location_change(
    from_country: str,
    to_country: str,
    time_diff_seconds: float,
) -> Dict[str, Any]:
    """Shortcut for GeoUtils.analyze_location_change."""
    return GeoUtils.analyze_location_change(
        from_country, to_country, time_diff_seconds
    )