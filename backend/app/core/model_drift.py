"""
Model Drift — Detection of model/data drift over time.

بيوفر:
- Data drift detection (KS test, PSI)
- Prediction drift detection (distribution comparison)
- Performance drift detection (metrics degradation)
- Baseline storage (mean, std, histogram, percentiles, data sample)
- Statistical significance testing
- Alert thresholds (warning + critical)
- Recommendations (retrain / investigate)
- Per-feature drift analysis
- Model persistence (save/load)
- Per-model state isolation

الفكرة:
- كل موديل عنده baseline لتوزيع البيانات وقت التدريب
- مع الوقت، بنقارن البيانات الحالية بالـ baseline
- لو الفرق كبير → drift detected → alert

الأنواع:
- Data Drift: توزيع الـ features اتغير
- Prediction Drift: توزيع الـ predictions اتغير
- Performance Drift: الدقة انخفضت

الاستخدام:
- ml_payload_detector.py
- anomaly_detection.py
- ensemble_anomaly.py
- monitoring
- admin dashboard
"""

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
import structlog
from scipy import stats

logger = structlog.get_logger()


class DriftSeverity:
    """مستويات الـ drift."""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ModelDrift:
    """
    Model Drift Detector.

    الفكرة:
    - baseline لكل موديل (يتضمن عينة من البيانات)
    - comparison مع البيانات الجديدة
    - KS test للدقة العالية + PSI كبديل
    - alerts حسب severity
    """

    # ─── Config ────────────────────────────────────────────
    STORAGE_DIR = "storage/drift"
    MAX_HISTORY = 100
    MAX_SAMPLE_SIZE = 1000

    # ─── KS test thresholds ───────────────────────────────
    # ملاحظة: مع large samples (500+)، الـ p-value بيبقى حساس جداً
    # فبنستخدم KS stat فقط للتصنيف
    KS_WARNING = 0.15
    KS_CRITICAL = 0.30
    KS_PVALUE_WARNING = 0.001
    KS_PVALUE_CRITICAL = 0.0001

    # ─── PSI thresholds ──────────────────────────────────
    # ملاحظة: sampling noise على 20 bins بيدي PSI ~0.10-0.15
    # فرفعنا الـ warning لـ 0.15
    PSI_WARNING = 0.15
    PSI_CRITICAL = 0.25

    # ─── Performance drift thresholds ─────────────────────
    PERFORMANCE_WARNING = 0.1    # 10% degradation
    PERFORMANCE_CRITICAL = 0.25  # 25% degradation

    # ─── State ────────────────────────────────────────────
    _baselines: Dict[str, Dict[str, Any]] = {}
    _history: Dict[str, List[Dict[str, Any]]] = {}
    _is_loaded: bool = False

    # ═══════════════════════════════════════════════════════
    #  Internal Helpers
    # ═══════════════════════════════════════════════════════

    @classmethod
    def _ensure_dir(cls) -> None:
        """بيتأكد إن مجلد الـ drift موجود."""
        Path(cls.STORAGE_DIR).mkdir(parents=True, exist_ok=True)

    @classmethod
    def _baseline_path(cls, model_name: str) -> str:
        """بيرجع مسار baseline موديل معين."""
        return os.path.join(cls.STORAGE_DIR, f"{model_name}_baseline.pkl")

    @classmethod
    def _history_path(cls, model_name: str) -> str:
        """بيرجع مسار history موديل معين."""
        return os.path.join(cls.STORAGE_DIR, f"{model_name}_history.json")

    # ═══════════════════════════════════════════════════════
    #  Baseline Creation
    # ═══════════════════════════════════════════════════════

    @classmethod
    def create_baseline(
        cls,
        model_name: str,
        X: np.ndarray,
        *,
        feature_names: Optional[List[str]] = None,
        n_bins: int = 20,
    ) -> Dict[str, Any]:
        """
        بيعمل baseline لتوزيع البيانات.

        Args:
            model_name: اسم الموديل
            X: بيانات التدريب (n_samples, n_features)
            feature_names: أسماء الـ features
            n_bins: عدد الـ bins للـ histogram

        Returns:
            dict فيه baseline stats
        """
        try:
            X = np.asarray(X, dtype=np.float64)
            if X.ndim == 1:
                X = X.reshape(-1, 1)

            if X.shape[0] < 10:
                return {
                    "success": False,
                    "error": "insufficient_samples",
                    "min_required": 10,
                    "got": int(X.shape[0]),
                }

            X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

            n_samples, n_features = X.shape

            if feature_names is None:
                feature_names = [f"feature_{i}" for i in range(n_features)]

            # ─── Per-feature stats ───
            features_stats = []
            histograms = []

            for i in range(n_features):
                col = X[:, i]

                feature_stats = {
                    "name": feature_names[i],
                    "mean": float(np.mean(col)),
                    "std": float(np.std(col)),
                    "min": float(np.min(col)),
                    "max": float(np.max(col)),
                    "median": float(np.median(col)),
                    "p25": float(np.percentile(col, 25)),
                    "p75": float(np.percentile(col, 75)),
                    "p95": float(np.percentile(col, 95)),
                    "p99": float(np.percentile(col, 99)),
                }
                features_stats.append(feature_stats)

                hist, edges = np.histogram(col, bins=n_bins)
                histograms.append({
                    "name": feature_names[i],
                    "counts": hist.tolist(),
                    "edges": edges.tolist(),
                    "total": int(np.sum(hist)),
                })

            # ─── Save data sample for KS test ───
            # نخزن عينة (max 1000) للـ KS test اللي بيحتاج البيانات الفعلية
            if n_samples <= cls.MAX_SAMPLE_SIZE:
                X_sample = X.copy()
            else:
                rng = np.random.RandomState(42)
                idx = rng.choice(n_samples, cls.MAX_SAMPLE_SIZE, replace=False)
                X_sample = X[idx].copy()

            baseline = {
                "model_name": model_name,
                "n_samples": int(n_samples),
                "n_features": int(n_features),
                "feature_names": feature_names,
                "features_stats": features_stats,
                "histograms": histograms,
                "data_sample": X_sample,
                "n_bins": int(n_bins),
                "created_at": time.time(),
                "version": "1.2",
            }

            cls._baselines[model_name] = baseline
            cls._history[model_name] = []

            logger.info(
                "drift_baseline_created",
                model_name=model_name,
                n_samples=n_samples,
                n_features=n_features,
                sample_size=len(X_sample),
            )

            return {
                "success": True,
                "model_name": model_name,
                "n_samples": n_samples,
                "n_features": n_features,
                "sample_size": len(X_sample),
            }

        except Exception as e:
            logger.error("drift_baseline_failed", error=str(e), model=model_name)
            return {"success": False, "error": str(e)}

    # ═══════════════════════════════════════════════════════
    #  KS Test (Kolmogorov-Smirnov)
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def _ks_test(
        baseline_data: np.ndarray,
        current_data: np.ndarray,
    ) -> Tuple[float, float]:
        """
        بيعمل KS test بين توزيعين.

        Returns:
            (ks_statistic, p_value)
        """
        try:
            ks_stat, p_value = stats.ks_2samp(baseline_data, current_data)
            return float(ks_stat), float(p_value)
        except Exception:
            return 0.0, 1.0

    # ═══════════════════════════════════════════════════════
    #  PSI (Population Stability Index)
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def _compute_psi(
        baseline_counts: np.ndarray,
        current_counts: np.ndarray,
    ) -> float:
        """
        بيعمل PSI بين توزيعين.

        PSI < 0.15  → no significant change
        PSI < 0.25  → moderate change (warning)
        PSI >= 0.25 → significant change (critical)
        """
        try:
            baseline_total = np.sum(baseline_counts)
            current_total = np.sum(current_counts)

            if baseline_total == 0 or current_total == 0:
                return 0.0

            baseline_pct = baseline_counts / baseline_total
            current_pct = current_counts / current_total

            epsilon = 1e-6
            baseline_pct = np.maximum(baseline_pct, epsilon)
            current_pct = np.maximum(current_pct, epsilon)

            psi = np.sum(
                (current_pct - baseline_pct)
                * np.log(current_pct / baseline_pct)
            )

            return float(abs(psi))
        except Exception:
            return 0.0

    # ═══════════════════════════════════════════════════════
    #  Out-of-Range Detection
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def _out_of_range_ratio(
        current_col: np.ndarray,
        baseline_edges: np.ndarray,
    ) -> float:
        """
        بيحسب نسبة البيانات الحالية اللي برة نطاق الـ baseline.

        Returns:
            ratio (0.0 - 1.0)
        """
        try:
            min_edge = baseline_edges[0]
            max_edge = baseline_edges[-1]

            out_of_range = np.sum(
                (current_col < min_edge) | (current_col > max_edge)
            )

            return float(out_of_range / len(current_col))
        except Exception:
            return 0.0

    # ═══════════════════════════════════════════════════════
    #  Drift Detection
    # ═══════════════════════════════════════════════════════

    @classmethod
    def detect_drift(
        cls,
        model_name: str,
        X_current: np.ndarray,
        *,
        method: str = "ks",
    ) -> Dict[str, Any]:
        """
        بيكشف الـ drift بين البيانات الحالية والـ baseline.

        Args:
            model_name: اسم الموديل
            X_current: البيانات الحالية (n_samples, n_features)
            method: "ks" (افتراضي) | "psi" | "both"

        Returns:
            dict فيه drift analysis
        """
        baseline = cls._baselines.get(model_name)

        if not baseline:
            return {
                "success": False,
                "error": "no_baseline",
                "model_name": model_name,
            }

        try:
            X_current = np.asarray(X_current, dtype=np.float64)
            if X_current.ndim == 1:
                X_current = X_current.reshape(-1, 1)

            if X_current.shape[0] < 10:
                return {
                    "success": False,
                    "error": "insufficient_samples",
                    "min_required": 10,
                    "got": int(X_current.shape[0]),
                }

            if X_current.shape[1] != baseline["n_features"]:
                return {
                    "success": False,
                    "error": "feature_dimension_mismatch",
                    "expected": baseline["n_features"],
                    "got": X_current.shape[1],
                }

            X_current = np.nan_to_num(X_current, nan=0.0, posinf=0.0, neginf=0.0)

            # ─── Per-feature drift ───
            feature_drifts = []
            drifted_features = 0
            max_psi = 0.0
            total_psi = 0.0
            max_ks = 0.0
            min_ks_pvalue = 1.0
            max_out_of_range = 0.0

            X_baseline_sample = baseline.get("data_sample")

            for i, hist in enumerate(baseline["histograms"]):
                col_current = X_current[:, i]

                # ─── KS test ───
                ks_stat = 0.0
                ks_pvalue = 1.0

                if X_baseline_sample is not None and method in ("ks", "both"):
                    col_baseline = X_baseline_sample[:, i]
                    ks_stat, ks_pvalue = cls._ks_test(
                        col_baseline, col_current
                    )

                # ─── PSI ───
                psi = 0.0
                if method in ("psi", "both"):
                    current_counts, _ = np.histogram(
                        col_current,
                        bins=np.array(hist["edges"]),
                    )
                    psi = cls._compute_psi(
                        np.array(hist["counts"]),
                        current_counts,
                    )
                else:
                    psi = ks_stat  # للعرض بس

                # ─── Out of range ratio ───
                out_of_range = cls._out_of_range_ratio(
                    col_current,
                    np.array(hist["edges"]),
                )

                # ─── Determine severity ───
                if method == "ks":
                    # معتمد على KS stat + out_of_range بس
                    # (الـ p-value مش موثوق مع large samples)
                    if (
                        ks_stat >= cls.KS_CRITICAL
                        or out_of_range > 0.5
                    ):
                        severity = DriftSeverity.CRITICAL
                        drifted_features += 1
                    elif (
                        ks_stat >= cls.KS_WARNING
                        or out_of_range > 0.2
                    ):
                        severity = DriftSeverity.MEDIUM
                        drifted_features += 1
                    elif ks_stat >= cls.KS_WARNING * 0.5:
                        severity = DriftSeverity.LOW
                    else:
                        severity = DriftSeverity.NONE
                else:
                    # معتمد على PSI + out_of_range
                    if psi >= cls.PSI_CRITICAL or out_of_range > 0.5:
                        severity = DriftSeverity.CRITICAL
                        drifted_features += 1
                    elif psi >= cls.PSI_WARNING or out_of_range > 0.2:
                        severity = DriftSeverity.MEDIUM
                        drifted_features += 1
                    elif psi >= cls.PSI_WARNING * 0.5:
                        severity = DriftSeverity.LOW
                    else:
                        severity = DriftSeverity.NONE

                feature_drifts.append({
                    "name": hist["name"],
                    "psi": round(psi, 4),
                    "ks_stat": round(ks_stat, 4),
                    "ks_pvalue": round(ks_pvalue, 6),
                    "out_of_range_ratio": round(out_of_range, 4),
                    "severity": severity,
                    "is_drifted": severity in (
                        DriftSeverity.CRITICAL,
                        DriftSeverity.MEDIUM,
                    ),
                })

                max_psi = max(max_psi, psi)
                max_ks = max(max_ks, ks_stat)
                min_ks_pvalue = min(min_ks_pvalue, ks_pvalue)
                max_out_of_range = max(max_out_of_range, out_of_range)
                total_psi += psi

            avg_psi = total_psi / len(feature_drifts) if feature_drifts else 0.0

            # ─── Overall drift ───
            if method == "ks":
                if (
                    max_ks >= cls.KS_CRITICAL
                    or max_out_of_range > 0.5
                ):
                    overall_severity = DriftSeverity.CRITICAL
                elif (
                    max_ks >= cls.KS_WARNING
                    or max_out_of_range > 0.2
                ):
                    overall_severity = DriftSeverity.MEDIUM
                elif max_ks >= cls.KS_WARNING * 0.5:
                    overall_severity = DriftSeverity.LOW
                else:
                    overall_severity = DriftSeverity.NONE
            else:
                if max_psi >= cls.PSI_CRITICAL or max_out_of_range > 0.5:
                    overall_severity = DriftSeverity.CRITICAL
                elif max_psi >= cls.PSI_WARNING or max_out_of_range > 0.2:
                    overall_severity = DriftSeverity.MEDIUM
                elif avg_psi >= cls.PSI_WARNING * 0.5:
                    overall_severity = DriftSeverity.LOW
                else:
                    overall_severity = DriftSeverity.NONE

            is_drifted = overall_severity in (
                DriftSeverity.CRITICAL,
                DriftSeverity.MEDIUM,
            )

            drift_ratio = drifted_features / len(feature_drifts) if feature_drifts else 0.0

            # ─── Recommendation ───
            if overall_severity == DriftSeverity.CRITICAL:
                recommendation = "retrain_immediately"
            elif overall_severity == DriftSeverity.MEDIUM:
                recommendation = "investigate_and_retrain"
            elif overall_severity == DriftSeverity.LOW:
                recommendation = "monitor_closely"
            else:
                recommendation = "no_action"

            result = {
                "success": True,
                "model_name": model_name,
                "method": method,
                "n_samples": int(X_current.shape[0]),
                "is_drifted": is_drifted,
                "severity": overall_severity,
                "avg_psi": round(avg_psi, 4),
                "max_psi": round(max_psi, 4),
                "max_ks": round(max_ks, 4),
                "min_ks_pvalue": round(min_ks_pvalue, 6),
                "max_out_of_range": round(max_out_of_range, 4),
                "drifted_features": drifted_features,
                "total_features": len(feature_drifts),
                "drift_ratio": round(drift_ratio, 4),
                "features": feature_drifts,
                "recommendation": recommendation,
                "detected_at": time.time(),
            }

            # ─── Save to history ───
            if model_name not in cls._history:
                cls._history[model_name] = []

            cls._history[model_name].append({
                "timestamp": result["detected_at"],
                "severity": overall_severity,
                "avg_psi": result["avg_psi"],
                "max_psi": result["max_psi"],
                "max_ks": result["max_ks"],
                "drift_ratio": result["drift_ratio"],
            })

            if len(cls._history[model_name]) > cls.MAX_HISTORY:
                cls._history[model_name] = cls._history[model_name][-cls.MAX_HISTORY:]

            if is_drifted:
                logger.warning(
                    "model_drift_detected",
                    model_name=model_name,
                    severity=overall_severity,
                    avg_psi=round(avg_psi, 4),
                    max_ks=round(max_ks, 4),
                    recommendation=recommendation,
                )
            else:
                logger.info(
                    "model_drift_check",
                    model_name=model_name,
                    severity=overall_severity,
                    avg_psi=round(avg_psi, 4),
                    max_ks=round(max_ks, 4),
                )

            return result

        except Exception as e:
            logger.error("drift_detection_failed", error=str(e), model=model_name)
            return {"success": False, "error": str(e)}

    # ═══════════════════════════════════════════════════════
    #  Performance Drift
    # ═══════════════════════════════════════════════════════

    @classmethod
    def detect_performance_drift(
        cls,
        model_name: str,
        current_metrics: Dict[str, float],
        baseline_metrics: Optional[Dict[str, float]] = None,
    ) -> Dict[str, Any]:
        """
        بيكشف الـ drift في أداء الموديل.

        Args:
            model_name: اسم الموديل
            current_metrics: {metric_name: value} الحالية
            baseline_metrics: {metric_name: value} الأساسية

        Returns:
            dict فيه performance drift analysis
        """
        try:
            baseline = cls._baselines.get(model_name)
            if baseline and not baseline_metrics:
                baseline_metrics = baseline.get("performance_metrics", {})

            if not baseline_metrics:
                return {
                    "success": False,
                    "error": "no_baseline_metrics",
                    "model_name": model_name,
                }

            # ─── Compare metrics ───
            metric_drifts = []
            max_degradation = 0.0
            degraded_count = 0

            for metric_name, current_value in current_metrics.items():
                baseline_value = baseline_metrics.get(metric_name)

                if baseline_value is None:
                    continue

                # compute degradation
                if baseline_value == 0:
                    degradation = 0.0
                else:
                    degradation = abs(current_value - baseline_value) / abs(baseline_value)

                # determine severity
                if degradation >= cls.PERFORMANCE_CRITICAL:
                    severity = DriftSeverity.CRITICAL
                    degraded_count += 1
                elif degradation >= cls.PERFORMANCE_WARNING:
                    severity = DriftSeverity.MEDIUM
                    degraded_count += 1
                elif degradation >= cls.PERFORMANCE_WARNING * 0.5:
                    severity = DriftSeverity.LOW
                else:
                    severity = DriftSeverity.NONE

                metric_drifts.append({
                    "name": metric_name,
                    "baseline_value": round(baseline_value, 4),
                    "current_value": round(current_value, 4),
                    "degradation": round(degradation, 4),
                    "severity": severity,
                })

                max_degradation = max(max_degradation, degradation)

            # ─── Overall ───
            if max_degradation >= cls.PERFORMANCE_CRITICAL:
                overall_severity = DriftSeverity.CRITICAL
            elif max_degradation >= cls.PERFORMANCE_WARNING:
                overall_severity = DriftSeverity.MEDIUM
            elif max_degradation >= cls.PERFORMANCE_WARNING * 0.5:
                overall_severity = DriftSeverity.LOW
            else:
                overall_severity = DriftSeverity.NONE

            is_drifted = overall_severity in (
                DriftSeverity.CRITICAL,
                DriftSeverity.MEDIUM,
            )

            # ─── Recommendation ───
            if overall_severity == DriftSeverity.CRITICAL:
                recommendation = "retrain_immediately"
            elif overall_severity == DriftSeverity.MEDIUM:
                recommendation = "investigate_and_retrain"
            elif overall_severity == DriftSeverity.LOW:
                recommendation = "monitor"
            else:
                recommendation = "no_action"

            result = {
                "success": True,
                "model_name": model_name,
                "is_drifted": is_drifted,
                "severity": overall_severity,
                "max_degradation": round(max_degradation, 4),
                "degraded_metrics": degraded_count,
                "total_metrics": len(metric_drifts),
                "metrics": metric_drifts,
                "recommendation": recommendation,
                "detected_at": time.time(),
            }

            if is_drifted:
                logger.warning(
                    "performance_drift_detected",
                    model_name=model_name,
                    severity=overall_severity,
                    max_degradation=round(max_degradation, 4),
                )

            return result

        except Exception as e:
            logger.error("performance_drift_failed", error=str(e))
            return {"success": False, "error": str(e)}

    # ═══════════════════════════════════════════════════════
    #  Performance Baseline
    # ═══════════════════════════════════════════════════════

    @classmethod
    def set_performance_baseline(
        cls,
        model_name: str,
        metrics: Dict[str, float],
    ) -> Dict[str, Any]:
        """بيحدد الـ performance baseline لموديل."""
        if model_name not in cls._baselines:
            return {
                "success": False,
                "error": "no_baseline",
                "model_name": model_name,
            }

        cls._baselines[model_name]["performance_metrics"] = dict(metrics)
        cls._baselines[model_name]["performance_set_at"] = time.time()

        logger.info(
            "performance_baseline_set",
            model_name=model_name,
            metrics=list(metrics.keys()),
        )

        return {"success": True, "model_name": model_name}

    # ═══════════════════════════════════════════════════════
    #  History
    # ═══════════════════════════════════════════════════════

    @classmethod
    def get_history(
        cls,
        model_name: str,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """بيرجع تاريخ الـ drift checks."""
        return cls._history.get(model_name, [])[-limit:]

    @classmethod
    def get_latest(
        cls,
        model_name: str,
    ) -> Optional[Dict[str, Any]]:
        """بيرجع آخر drift check."""
        history = cls._history.get(model_name, [])
        return history[-1] if history else None

    @classmethod
    def get_trend(
        cls,
        model_name: str,
        last_n: int = 10,
    ) -> Dict[str, Any]:
        """بيحلل اتجاه الـ drift."""
        history = cls._history.get(model_name, [])[-last_n:]

        if len(history) < 2:
            return {
                "success": False,
                "error": "insufficient_history",
            }

        avg_psi_values = [h["avg_psi"] for h in history]

        n = len(avg_psi_values)
        x = np.arange(n)
        y = np.array(avg_psi_values)

        try:
            slope, intercept = np.polyfit(x, y, 1)
            trend = "increasing" if slope > 0.01 else ("decreasing" if slope < -0.01 else "stable")
        except Exception:
            slope = 0.0
            trend = "unknown"

        return {
            "success": True,
            "model_name": model_name,
            "n_points": n,
            "trend": trend,
            "slope": round(float(slope), 6),
            "avg_psi_first": round(avg_psi_values[0], 4),
            "avg_psi_last": round(avg_psi_values[-1], 4),
            "avg_psi_mean": round(float(np.mean(avg_psi_values)), 4),
        }

    # ═══════════════════════════════════════════════════════
    #  Status
    # ═══════════════════════════════════════════════════════

    @classmethod
    def get_status(cls) -> Dict[str, Any]:
        """بيرجع حالة الـ drift لكل الموديلات."""
        status = {}

        for model_name, baseline in cls._baselines.items():
            latest = cls.get_latest(model_name)
            status[model_name] = {
                "has_baseline": True,
                "baseline_created_at": baseline.get("created_at"),
                "n_samples_baseline": baseline.get("n_samples"),
                "n_features": baseline.get("n_features"),
                "checks_count": len(cls._history.get(model_name, [])),
                "latest_severity": latest.get("severity") if latest else None,
                "latest_avg_psi": latest.get("avg_psi") if latest else None,
            }

        return {
            "total_models": len(cls._baselines),
            "models": status,
        }

    @classmethod
    def has_baseline(cls, model_name: str) -> bool:
        """بيتحقق لو فيه baseline."""
        return model_name in cls._baselines

    @classmethod
    def list_models(cls) -> List[str]:
        """بيرجع أسماء الموديلات اللي عندها baseline."""
        return list(cls._baselines.keys())

    # ═══════════════════════════════════════════════════════
    #  Persistence
    # ═══════════════════════════════════════════════════════

    @classmethod
    def save_baseline(
        cls,
        model_name: str,
    ) -> Dict[str, Any]:
        """بيحفظ baseline موديل على disk."""
        baseline = cls._baselines.get(model_name)
        if not baseline:
            return {
                "success": False,
                "error": "no_baseline",
                "model_name": model_name,
            }

        try:
            cls._ensure_dir()
            path = cls._baseline_path(model_name)

            joblib.dump(baseline, path)

            history_path = cls._history_path(model_name)
            with open(history_path, "w", encoding="utf-8") as f:
                json.dump(cls._history.get(model_name, []), f, indent=2)

            logger.info("drift_baseline_saved", model_name=model_name, path=path)

            return {
                "success": True,
                "model_name": model_name,
                "path": path,
                "size_bytes": os.path.getsize(path),
            }

        except Exception as e:
            logger.error("drift_baseline_save_failed", error=str(e))
            return {"success": False, "error": str(e)}

    @classmethod
    def load_baseline(
        cls,
        model_name: str,
    ) -> Dict[str, Any]:
        """بيحمّل baseline موديل من disk."""
        try:
            path = cls._baseline_path(model_name)

            if not os.path.exists(path):
                return {
                    "success": False,
                    "error": "baseline_file_not_found",
                    "path": path,
                }

            baseline = joblib.load(path)
            cls._baselines[model_name] = baseline

            history_path = cls._history_path(model_name)
            if os.path.exists(history_path):
                try:
                    with open(history_path, "r", encoding="utf-8") as f:
                        cls._history[model_name] = json.load(f)
                except json.JSONDecodeError:
                    cls._history[model_name] = []
            else:
                cls._history[model_name] = []

            logger.info("drift_baseline_loaded", model_name=model_name)

            return {
                "success": True,
                "model_name": model_name,
                "path": path,
                "created_at": baseline.get("created_at"),
            }

        except Exception as e:
            logger.error("drift_baseline_load_failed", error=str(e))
            return {"success": False, "error": str(e)}

    @classmethod
    def load_all(cls) -> Dict[str, Any]:
        """بيحمّل كل الـ baselines."""
        loaded = []
        failed = []

        if not os.path.exists(cls.STORAGE_DIR):
            return {
                "success": True,
                "loaded": [],
                "failed": [],
            }

        for filename in os.listdir(cls.STORAGE_DIR):
            if filename.endswith("_baseline.pkl"):
                model_name = filename.replace("_baseline.pkl", "")
                result = cls.load_baseline(model_name)
                if result.get("success"):
                    loaded.append(model_name)
                else:
                    failed.append(model_name)

        cls._is_loaded = True

        logger.info(
            "drift_load_all_done",
            loaded=len(loaded),
            failed=len(failed),
        )

        return {
            "success": True,
            "loaded": loaded,
            "failed": failed,
        }

    @classmethod
    def delete_baseline(
        cls,
        model_name: str,
    ) -> bool:
        """بيمسح baseline موديل."""
        try:
            deleted = False

            baseline_path = cls._baseline_path(model_name)
            if os.path.exists(baseline_path):
                os.remove(baseline_path)
                deleted = True

            history_path = cls._history_path(model_name)
            if os.path.exists(history_path):
                os.remove(history_path)
                deleted = True

            cls._baselines.pop(model_name, None)
            cls._history.pop(model_name, None)

            return deleted

        except Exception as e:
            logger.error("drift_baseline_delete_failed", error=str(e))
            return False

    # ═══════════════════════════════════════════════════════
    #  Utilities
    # ═══════════════════════════════════════════════════════

    @classmethod
    def clear(cls) -> None:
        """بيمسح كل الـ baselines من الـ memory (مش من disk)."""
        cls._baselines = {}
        cls._history = {}
        cls._is_loaded = False
        logger.info("drift_cleared")

    @classmethod
    def get_baseline_info(
        cls,
        model_name: str,
    ) -> Optional[Dict[str, Any]]:
        """بيرجع معلومات الـ baseline."""
        baseline = cls._baselines.get(model_name)
        if not baseline:
            return None

        return {
            "model_name": model_name,
            "n_samples": baseline.get("n_samples"),
            "n_features": baseline.get("n_features"),
            "feature_names": baseline.get("feature_names", []),
            "created_at": baseline.get("created_at"),
            "has_performance_metrics": "performance_metrics" in baseline,
            "has_data_sample": "data_sample" in baseline,
        }


# ─── Standalone functions ─────────────────────────────

def create_baseline(
    model_name: str,
    X: np.ndarray,
    **kwargs,
) -> Dict[str, Any]:
    """Shortcut for ModelDrift.create_baseline."""
    return ModelDrift.create_baseline(model_name, X, **kwargs)


def detect_drift(
    model_name: str,
    X_current: np.ndarray,
    **kwargs,
) -> Dict[str, Any]:
    """Shortcut for ModelDrift.detect_drift."""
    return ModelDrift.detect_drift(model_name, X_current, **kwargs)


def detect_performance_drift(
    model_name: str,
    current_metrics: Dict[str, float],
    **kwargs,
) -> Dict[str, Any]:
    """Shortcut for ModelDrift.detect_performance_drift."""
    return ModelDrift.detect_performance_drift(
        model_name, current_metrics, **kwargs
    )


def get_drift_status() -> Dict[str, Any]:
    """Shortcut for ModelDrift.get_status."""
    return ModelDrift.get_status()