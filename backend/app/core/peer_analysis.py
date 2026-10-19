"""
Peer Analysis — Compare user behavior against peer group.

بيوفر:
- Peer group management (تسجيل + إضافة/إزالة أعضاء)
- Per-user metrics tracking
- Group baseline computation (mean, std, percentiles)
- User vs peers comparison
- Outlier detection (Z-score + IQR)
- Anomaly scoring
- Redis-backed

الفكرة:
- كل مستخدم عنده peer group (مثلاً: "admins", "developers")
- بنبني baseline جماعي للـ group
- لو مستخدم سلوكه مختلف بشكل كبير عن أقرانه → anomaly
- مناسب لـ:
  * Insider threat detection
  * Privilege abuse detection
  * Compromised account detection

الفرق عن user_baseline:
- user_baseline: مقارنة المستخدم بنفسه (personal)
- peer_analysis: مقارنة المستخدم بأقرانه (group)

الاستخدام:
- session_analyzer.py
- anomaly_detection.py
- defense_service.py
"""

import json
import math
import time
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import redis.asyncio as redis
import structlog

from app.core.config import settings

logger = structlog.get_logger()


class PeerAnalysis:
    """
    Peer Group Behavior Analysis.

    الفكرة:
    - بنجمع metrics لكل مستخدم
    - بنحسب baseline لكل peer group
    - بنقارن كل مستخدم بالأقران
    """

    _redis_client: Optional[redis.Redis] = None

    # ─── Config ────────────────────────────────────────────
    METRICS_TTL = 86400 * 30     # 30 يوم
    GROUP_TTL = 86400 * 90       # 90 يوم
    BASELINE_TTL = 86400 * 7     # 7 أيام

    # ─── Thresholds ────────────────────────────────────────
    MIN_PEERS = 3                # أقل عدد في الـ peer group
    MIN_DATA_POINTS = 5          # أقل عدد metrics لكل user
    Z_SCORE_THRESHOLD = 2.5      # threshold للـ outlier detection
    IQR_MULTIPLIER = 1.5         # للـ IQR method

    # ─── Metric Names ──────────────────────────────────────
    METRICS = [
        "logins_per_day",
        "unique_ips",
        "unique_countries",
        "unique_devices",
        "unique_endpoints",
        "avg_session_duration_min",
        "failed_logins",
        "off_hours_ratio",
        "actions_per_session",
        "data_accessed_mb",
    ]

    # ─── Weights ──────────────────────────────────────────
    WEIGHTS = {
        "extreme_outlier": 50,      # Z-score > 3
        "strong_outlier": 35,       # Z-score > 2.5
        "moderate_outlier": 20,     # Z-score > 2
        "many_outliers": 30,        # >= 3 metrics كـ outliers
        "consistent_outlier": 25,   # نفس الـ metric دايماً outlier
        "privilege_abuse": 40,      # مستخدم منخفض الصلاحيات بيعمل حاجات admin
    }

    # ─── Risk Thresholds ──────────────────────────────────
    THRESHOLDS = {
        "low": 30,
        "medium": 50,
        "high": 70,
        "critical": 85,
    }

    # ─── Internal Helpers ─────────────────────────────────

    @classmethod
    def get_client(cls) -> Optional[redis.Redis]:
        """Lazy Redis client."""
        if cls._redis_client is None:
            try:
                cls._redis_client = redis.from_url(
                    settings.REDIS_URL,
                    decode_responses=True,
                    socket_connect_timeout=5,
                    socket_timeout=5,
                )
            except Exception as e:
                logger.error("peer_analysis_redis_init_failed", error=str(e))
                return None
        return cls._redis_client

    @staticmethod
    def _group_key(group_name: str) -> str:
        return f"peer:group:{group_name}"

    @staticmethod
    def _group_members_key(group_name: str) -> str:
        return f"peer:group:{group_name}:members"

    @staticmethod
    def _user_group_key(user_id: str) -> str:
        return f"peer:user:{user_id}:group"

    @staticmethod
    def _user_metrics_key(user_id: str) -> str:
        return f"peer:user:{user_id}:metrics"

    @staticmethod
    def _group_baseline_key(group_name: str) -> str:
        return f"peer:group:{group_name}:baseline"

    # ═══════════════════════════════════════════════════════
    #  Peer Group Management
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def register_group(
        cls,
        group_name: str,
        *,
        description: str = "",
        role: str = "",
    ) -> Dict[str, Any]:
        """
        بيسجل peer group جديد.

        Args:
            group_name: اسم المجموعة (مثلاً: "admins")
            description: وصف
            role: الدور المرتبط

        Returns:
            dict فيه success
        """
        client = cls.get_client()
        if not client:
            return {"success": False, "error": "redis_unavailable"}

        try:
            if not group_name:
                return {"success": False, "error": "missing_group_name"}

            group_data = {
                "name": group_name,
                "description": description,
                "role": role,
                "created_at": time.time(),
            }

            group_key = cls._group_key(group_name)
            await client.set(
                group_key,
                json.dumps(group_data),
                ex=cls.GROUP_TTL,
            )

            logger.info("peer_group_registered", group_name=group_name)

            return {"success": True, "group_name": group_name}

        except Exception as e:
            logger.error("peer_group_register_failed", error=str(e))
            return {"success": False, "error": str(e)}

    @classmethod
    async def add_user_to_group(
        cls,
        user_id: str,
        group_name: str,
    ) -> Dict[str, Any]:
        """بيضيف مستخدم لـ peer group."""
        client = cls.get_client()
        if not client:
            return {"success": False, "error": "redis_unavailable"}

        try:
            # تحقق إن الـ group موجودة
            group_key = cls._group_key(group_name)
            if not await client.exists(group_key):
                # نعملها automatically
                await cls.register_group(group_name)

            # ضيف العضو
            members_key = cls._group_members_key(group_name)
            await client.sadd(members_key, user_id)
            await client.expire(members_key, cls.GROUP_TTL)

            # سجل الـ group بتاعة المستخدم
            user_group_key = cls._user_group_key(user_id)
            await client.set(user_group_key, group_name, ex=cls.GROUP_TTL)

            logger.info(
                "peer_user_added",
                user_id=user_id,
                group_name=group_name,
            )

            return {"success": True, "user_id": user_id, "group": group_name}

        except Exception as e:
            logger.error("peer_add_user_failed", error=str(e))
            return {"success": False, "error": str(e)}

    @classmethod
    async def remove_user_from_group(
        cls,
        user_id: str,
        group_name: str,
    ) -> Dict[str, Any]:
        """بيشيل مستخدم من الـ group."""
        client = cls.get_client()
        if not client:
            return {"success": False, "error": "redis_unavailable"}

        try:
            members_key = cls._group_members_key(group_name)
            await client.srem(members_key, user_id)

            user_group_key = cls._user_group_key(user_id)
            await client.delete(user_group_key)

            # أعد حساب الـ baseline
            await cls.compute_group_baseline(group_name)

            logger.info(
                "peer_user_removed",
                user_id=user_id,
                group_name=group_name,
            )

            return {"success": True}

        except Exception as e:
            logger.error("peer_remove_user_failed", error=str(e))
            return {"success": False, "error": str(e)}

    @classmethod
    async def get_user_group(cls, user_id: str) -> Optional[str]:
        """بيرجع اسم الـ group بتاعة المستخدم."""
        client = cls.get_client()
        if not client:
            return None

        try:
            return await client.get(cls._user_group_key(user_id))
        except Exception as e:
            logger.error("peer_get_user_group_failed", error=str(e))
            return None

    @classmethod
    async def get_group_members(cls, group_name: str) -> List[str]:
        """بيرجع أعضاء الـ group."""
        client = cls.get_client()
        if not client:
            return []

        try:
            members_key = cls._group_members_key(group_name)
            return list(await client.smembers(members_key))
        except Exception as e:
            logger.error("peer_get_members_failed", error=str(e))
            return []

    # ═══════════════════════════════════════════════════════
    #  Metrics Recording
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def update_user_metrics(
        cls,
        user_id: str,
        metrics: Dict[str, float],
    ) -> Dict[str, Any]:
        """
        بيحدّث metrics المستخدم.

        Args:
            user_id: ID المستخدم
            metrics: dict فيه الـ metrics (بنفس أسماء cls.METRICS)

        Returns:
            dict فيه success
        """
        client = cls.get_client()
        if not client:
            return {"success": False, "error": "redis_unavailable"}

        try:
            if not user_id:
                return {"success": False, "error": "missing_user_id"}

            # تحقق من الـ metrics
            filtered = {}
            for key in cls.METRICS:
                if key in metrics:
                    try:
                        val = float(metrics[key])
                        if np.isfinite(val):
                            filtered[key] = val
                    except (ValueError, TypeError):
                        continue

            if not filtered:
                return {"success": False, "error": "no_valid_metrics"}

            # خزّن metric جديد (list of snapshots)
            metrics_key = cls._user_metrics_key(user_id)
            entry = {
                "timestamp": time.time(),
                "metrics": filtered,
            }
            await client.lpush(metrics_key, json.dumps(entry))
            await client.ltrim(metrics_key, 0, 99)  # آخر 100 snapshot
            await client.expire(metrics_key, cls.METRICS_TTL)

            return {
                "success": True,
                "user_id": user_id,
                "metrics_recorded": len(filtered),
            }

        except Exception as e:
            logger.error("peer_update_metrics_failed", error=str(e))
            return {"success": False, "error": str(e)}

    @classmethod
    async def get_user_metrics(
        cls,
        user_id: str,
        limit: int = 30,
    ) -> List[Dict[str, Any]]:
        """بيرجع metrics المستخدم (آخر snapshots)."""
        client = cls.get_client()
        if not client:
            return []

        try:
            metrics_key = cls._user_metrics_key(user_id)
            raw_list = await client.lrange(metrics_key, 0, limit - 1)

            snapshots = []
            for raw in raw_list:
                try:
                    snapshots.append(json.loads(raw))
                except json.JSONDecodeError:
                    continue

            return snapshots
        except Exception as e:
            logger.error("peer_get_metrics_failed", error=str(e))
            return []

    # ═══════════════════════════════════════════════════════
    #  Group Baseline
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def compute_group_baseline(
        cls,
        group_name: str,
    ) -> Dict[str, Any]:
        """
        بيحسب baseline للـ peer group.

        Returns:
            dict فيه mean, std, percentiles لكل metric
        """
        client = cls.get_client()
        if not client:
            return {"success": False, "error": "redis_unavailable"}

        try:
            members = await cls.get_group_members(group_name)

            if len(members) < cls.MIN_PEERS:
                return {
                    "success": False,
                    "error": "insufficient_peers",
                    "min_required": cls.MIN_PEERS,
                    "got": len(members),
                }

            # اجمع الـ metrics من كل الأعضاء
            all_metrics: Dict[str, List[float]] = {
                m: [] for m in cls.METRICS
            }

            for user_id in members:
                snapshots = await cls.get_user_metrics(user_id, limit=30)

                if len(snapshots) < cls.MIN_DATA_POINTS:
                    continue

                # احسب متوسط كل metric للمستخدم ده
                user_metric_values: Dict[str, List[float]] = {
                    m: [] for m in cls.METRICS
                }

                for snap in snapshots:
                    for metric_name, val in snap.get("metrics", {}).items():
                        if metric_name in user_metric_values:
                            user_metric_values[metric_name].append(val)

                # أضف متوسط المستخدم للـ group
                for metric_name, values in user_metric_values.items():
                    if values:
                        all_metrics[metric_name].append(float(np.mean(values)))

            # احسب baseline stats
            baseline: Dict[str, Dict[str, float]] = {}
            for metric_name, values in all_metrics.items():
                if len(values) < 2:
                    continue

                arr = np.array(values)

                baseline[metric_name] = {
                    "mean": float(np.mean(arr)),
                    "std": float(np.std(arr)),
                    "min": float(np.min(arr)),
                    "max": float(np.max(arr)),
                    "median": float(np.median(arr)),
                    "p25": float(np.percentile(arr, 25)),
                    "p75": float(np.percentile(arr, 75)),
                    "p95": float(np.percentile(arr, 95)),
                    "p99": float(np.percentile(arr, 99)),
                    "n_users": len(values),
                }

            if not baseline:
                return {
                    "success": False,
                    "error": "no_valid_data",
                }

            # خزّن
            group_baseline_key = cls._group_baseline_key(group_name)
            payload = {
                "group_name": group_name,
                "n_members": len(members),
                "metrics": baseline,
                "computed_at": time.time(),
            }
            await client.set(
                group_baseline_key,
                json.dumps(payload),
                ex=cls.BASELINE_TTL,
            )

            logger.info(
                "peer_group_baseline_computed",
                group_name=group_name,
                members=len(members),
                metrics_computed=len(baseline),
            )

            return {
                "success": True,
                "group_name": group_name,
                "n_members": len(members),
                "metrics_computed": len(baseline),
            }

        except Exception as e:
            logger.error("peer_compute_baseline_failed", error=str(e))
            return {"success": False, "error": str(e)}

    @classmethod
    async def get_group_baseline(
        cls,
        group_name: str,
    ) -> Optional[Dict[str, Any]]:
        """بيرجع baseline الـ group."""
        client = cls.get_client()
        if not client:
            return None

        try:
            raw = await client.get(cls._group_baseline_key(group_name))
            if not raw:
                return None
            return json.loads(raw)
        except Exception as e:
            logger.error("peer_get_baseline_failed", error=str(e))
            return None

    # ═══════════════════════════════════════════════════════
    #  Outlier Detection
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def _z_score(value: float, mean: float, std: float) -> float:
        """بيحسب z-score."""
        if std == 0 or not np.isfinite(std):
            return 0.0
        return (value - mean) / std

    @staticmethod
    def _is_outlier_iqr(
        value: float,
        p25: float,
        p75: float,
        multiplier: float = 1.5,
    ) -> bool:
        """بيتحقق لو القيمة outlier بـ IQR method."""
        iqr = p75 - p25
        if iqr <= 0:
            return False

        lower = p25 - multiplier * iqr
        upper = p75 + multiplier * iqr

        return value < lower or value > upper

    @classmethod
    def _classify_outlier(
        cls,
        z_score: float,
    ) -> Tuple[str, int]:
        """
        بيصنّف الـ outlier حسب z-score.

        Returns:
            (severity_label, weight)
        """
        abs_z = abs(z_score)

        if abs_z >= 3.0:
            return "extreme", cls.WEIGHTS["extreme_outlier"]
        elif abs_z >= 2.5:
            return "strong", cls.WEIGHTS["strong_outlier"]
        elif abs_z >= 2.0:
            return "moderate", cls.WEIGHTS["moderate_outlier"]
        else:
            return "none", 0

    # ═══════════════════════════════════════════════════════
    #  Main Analysis
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def analyze_user_vs_peers(
        cls,
        user_id: str,
    ) -> Dict[str, Any]:
        """
        بيحلل المستخدم مقارنة بأقرانه.

        Returns:
            dict فيه:
            - is_anomalous: bool
            - deviation_score: 0-100
            - level: clean/low/medium/high/critical
            - signals: list
            - outlier_metrics: list
            - details: تفاصيل
        """
        # 1. جيب الـ group
        group_name = await cls.get_user_group(user_id)

        if not group_name:
            return {
                "success": True,
                "user_id": user_id,
                "is_anomalous": False,
                "deviation_score": 0,
                "level": "no_group",
                "signals": [],
                "outlier_metrics": [],
                "details": {},
                "has_group": False,
            }

        # 2. جيب الـ baseline
        baseline = await cls.get_group_baseline(group_name)

        if not baseline:
            # حاول نحسبها
            result = await cls.compute_group_baseline(group_name)
            if not result.get("success"):
                return {
                    "success": True,
                    "user_id": user_id,
                    "is_anomalous": False,
                    "deviation_score": 0,
                    "level": "no_baseline",
                    "signals": [],
                    "outlier_metrics": [],
                    "details": {},
                    "has_group": True,
                    "group": group_name,
                }
            baseline = await cls.get_group_baseline(group_name)

        if not baseline:
            return {
                "success": False,
                "error": "no_baseline_available",
                "user_id": user_id,
            }

        try:
            # 3. جيب metrics المستخدم
            snapshots = await cls.get_user_metrics(user_id, limit=30)

            if len(snapshots) < cls.MIN_DATA_POINTS:
                return {
                    "success": True,
                    "user_id": user_id,
                    "is_anomalous": False,
                    "deviation_score": 0,
                    "level": "insufficient_data",
                    "signals": [],
                    "outlier_metrics": [],
                    "details": {
                        "min_required": cls.MIN_DATA_POINTS,
                        "got": len(snapshots),
                    },
                    "has_group": True,
                    "group": group_name,
                }

            # 4. احسب متوسط المستخدم لكل metric
            user_metrics: Dict[str, List[float]] = {
                m: [] for m in cls.METRICS
            }
            for snap in snapshots:
                for metric_name, val in snap.get("metrics", {}).items():
                    if metric_name in user_metrics:
                        user_metrics[metric_name].append(val)

            user_avg: Dict[str, float] = {}
            for metric_name, values in user_metrics.items():
                if values:
                    user_avg[metric_name] = float(np.mean(values))

            # 5. قارن كل metric
            signals: List[str] = []
            details: Dict[str, Any] = {}
            outlier_metrics: List[Dict[str, Any]] = []
            total_score = 0

            group_metrics = baseline.get("metrics", {})

            for metric_name, user_value in user_avg.items():
                group_stat = group_metrics.get(metric_name)
                if not group_stat:
                    continue

                mean = group_stat["mean"]
                std = group_stat["std"]

                # z-score
                z = cls._z_score(user_value, mean, std)

                # IQR
                is_iqr = cls._is_outlier_iqr(
                    user_value,
                    group_stat["p25"],
                    group_stat["p75"],
                    cls.IQR_MULTIPLIER,
                )

                # صنّف
                severity, weight = cls._classify_outlier(z)

                if severity != "none" or is_iqr:
                    outlier_entry = {
                        "metric": metric_name,
                        "user_value": round(user_value, 2),
                        "group_mean": round(mean, 2),
                        "group_std": round(std, 2),
                        "z_score": round(z, 2),
                        "severity": severity,
                        "is_iqr_outlier": is_iqr,
                        "direction": "higher" if user_value > mean else "lower",
                    }
                    outlier_metrics.append(outlier_entry)
                    total_score += weight

                    if severity == "extreme":
                        signals.append(f"extreme_{metric_name}")
                    elif severity == "strong":
                        signals.append(f"strong_{metric_name}")
                    elif severity == "moderate":
                        signals.append(f"moderate_{metric_name}")

            # 6. عدد outliers
            n_outliers = len(outlier_metrics)

            if n_outliers >= 3:
                signals.append("many_outliers")
                total_score += cls.WEIGHTS["many_outliers"]

            # 7. Privilege abuse check
            # لو المستخدم عنده metrics أعلى بكثير من المتوسط في critical metrics
            critical_metrics = ["unique_endpoints", "data_accessed_mb", "unique_devices"]
            privilege_flags = 0

            for m in critical_metrics:
                if m in user_avg and m in group_metrics:
                    group_stat = group_metrics[m]
                    if group_stat["mean"] > 0:
                        ratio = user_avg[m] / group_stat["mean"]
                        if ratio >= 3.0:
                            privilege_flags += 1

            if privilege_flags >= 2:
                signals.append("privilege_abuse_pattern")
                total_score += cls.WEIGHTS["privilege_abuse"]

            # 8. Deviation score
            deviation_score = min(int(math.sqrt(total_score) * 10), 100)

            # 9. Level
            level = "clean"
            if deviation_score >= cls.THRESHOLDS["critical"]:
                level = "critical"
            elif deviation_score >= cls.THRESHOLDS["high"]:
                level = "high"
            elif deviation_score >= cls.THRESHOLDS["medium"]:
                level = "medium"
            elif deviation_score >= cls.THRESHOLDS["low"]:
                level = "low"

            # 10. Decision
            is_anomalous = deviation_score >= cls.THRESHOLDS["low"]

            if is_anomalous:
                logger.warning(
                    "peer_anomaly_detected",
                    user_id=user_id,
                    group=group_name,
                    deviation_score=deviation_score,
                    level=level,
                    n_outliers=n_outliers,
                )

            details["group"] = group_name
            details["n_peers"] = baseline.get("n_members", 0)
            details["outliers_count"] = n_outliers
            details["metrics_analyzed"] = len(user_avg)

            return {
                "success": True,
                "user_id": user_id,
                "group": group_name,
                "is_anomalous": is_anomalous,
                "deviation_score": deviation_score,
                "level": level,
                "signals": signals,
                "signal_count": len(signals),
                "outlier_metrics": outlier_metrics,
                "outlier_count": n_outliers,
                "details": details,
                "has_group": True,
            }

        except Exception as e:
            logger.error("peer_analysis_failed", error=str(e))
            return {"success": False, "error": str(e)}

    # ═══════════════════════════════════════════════════════
    #  Utilities
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def get_group_stats(
        cls,
        group_name: str,
    ) -> Dict[str, Any]:
        """بيرجع إحصائيات الـ group."""
        members = await cls.get_group_members(group_name)
        baseline = await cls.get_group_baseline(group_name)

        # جيب معلومات الـ group
        client = cls.get_client()
        group_info = None
        if client:
            try:
                raw = await client.get(cls._group_key(group_name))
                if raw:
                    group_info = json.loads(raw)
            except Exception:
                pass

        return {
            "group_name": group_name,
            "n_members": len(members),
            "members": members[:20],  # أول 20
            "has_baseline": baseline is not None,
            "baseline_metrics": (
                list(baseline.get("metrics", {}).keys())
                if baseline else []
            ),
            "group_info": group_info,
        }

    @classmethod
    async def get_user_stats(
        cls,
        user_id: str,
    ) -> Dict[str, Any]:
        """بيرجع إحصائيات المستخدم."""
        group_name = await cls.get_user_group(user_id)
        snapshots = await cls.get_user_metrics(user_id, limit=100)

        # احسب averages
        metric_values: Dict[str, List[float]] = {m: [] for m in cls.METRICS}
        for snap in snapshots:
            for metric_name, val in snap.get("metrics", {}).items():
                if metric_name in metric_values:
                    metric_values[metric_name].append(val)

        averages = {}
        for metric_name, values in metric_values.items():
            if values:
                averages[metric_name] = round(float(np.mean(values)), 2)

        return {
            "user_id": user_id,
            "group": group_name,
            "snapshots_count": len(snapshots),
            "avg_metrics": averages,
        }

    @classmethod
    async def reset_user_metrics(cls, user_id: str) -> Dict[str, Any]:
        """بيمسح metrics المستخدم."""
        client = cls.get_client()
        if not client:
            return {"success": False, "error": "redis_unavailable"}

        try:
            metrics_key = cls._user_metrics_key(user_id)
            await client.delete(metrics_key)

            logger.info("peer_user_metrics_reset", user_id=user_id)

            return {"success": True, "user_id": user_id}

        except Exception as e:
            logger.error("peer_reset_user_failed", error=str(e))
            return {"success": False, "error": str(e)}

    @classmethod
    async def clear_all(cls) -> None:
        """بيمسح كل بيانات الـ peer analysis."""
        client = cls.get_client()
        if not client:
            return

        try:
            cursor = 0
            while True:
                cursor, keys = await client.scan(
                    cursor=cursor,
                    match="peer:*",
                    count=100,
                )
                if keys:
                    await client.delete(*keys)
                if cursor == 0:
                    break

            logger.info("peer_analysis_all_cleared")
        except Exception as e:
            logger.error("peer_clear_all_failed", error=str(e))

    @classmethod
    async def close(cls) -> None:
        """بتقفل Redis."""
        if cls._redis_client:
            await cls._redis_client.close()
            cls._redis_client = None


# ─── Standalone functions ─────────────────────────────

async def register_group(
    group_name: str,
    **kwargs,
) -> Dict[str, Any]:
    """Shortcut for PeerAnalysis.register_group."""
    return await PeerAnalysis.register_group(group_name, **kwargs)


async def add_user_to_group(
    user_id: str,
    group_name: str,
) -> Dict[str, Any]:
    """Shortcut for PeerAnalysis.add_user_to_group."""
    return await PeerAnalysis.add_user_to_group(user_id, group_name)


async def update_user_metrics(
    user_id: str,
    metrics: Dict[str, float],
) -> Dict[str, Any]:
    """Shortcut for PeerAnalysis.update_user_metrics."""
    return await PeerAnalysis.update_user_metrics(user_id, metrics)


async def analyze_user_vs_peers(user_id: str) -> Dict[str, Any]:
    """Shortcut for PeerAnalysis.analyze_user_vs_peers."""
    return await PeerAnalysis.analyze_user_vs_peers(user_id)