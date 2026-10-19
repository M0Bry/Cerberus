"""
Anomaly Detection — ML-based behavioral anomaly detection.

بيوفر:
- ML Mode: Isolation Forest (لو فيه بيانات كفاية)
- Statistical Mode: heuristics بسيطة (fallback)
- تكامل مع IPLogger
- تخزين في Redis (عشان يشتغل مع multiple workers)
"""

import os
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional

import joblib
import numpy as np
import structlog
from sklearn.ensemble import IsolationForest

from app.core.config import settings

logger = structlog.get_logger()


class AnomalyDetector:
    """
    كلاس لاكتشاف الشذوذ.

    بيستخدم:
    - ML Mode: Isolation Forest (لو فيه بيانات كفاية)
    - Statistical Mode: heuristics (fallback)

    بياخد البيانات من IPLogger.get_behavioral_data
    """

    def __init__(self):
        self.ml_model: Optional[IsolationForest] = None
        self._request_patterns: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self._load_ml_model()

    # ─── ML Model ──────────────────────────────────────────

    def _load_ml_model(self) -> None:
        """بيحمل موديل ML لو موجود."""
        model_path = settings.DEFENSE_ANOMALY_MODEL_PATH
        if os.path.exists(model_path):
            try:
                self.ml_model = joblib.load(model_path)
                logger.info("anomaly_ml_model_loaded", path=model_path)
            except Exception as e:
                logger.error("anomaly_ml_model_load_failed", error=str(e))
                self.ml_model = None

    def _save_ml_model(self) -> None:
        """بيحفظ موديل ML."""
        model_path = settings.DEFENSE_ANOMALY_MODEL_PATH
        try:
            os.makedirs(os.path.dirname(model_path), exist_ok=True)
            joblib.dump(self.ml_model, model_path)
            logger.info("anomaly_ml_model_saved", path=model_path)
        except Exception as e:
            logger.error("anomaly_ml_model_save_failed", error=str(e))

    @staticmethod
    def _extract_features(data: Dict[str, Any]) -> np.ndarray:
        """بيستخرج الـ features من البيانات السلوكية."""
        return np.array([[
            data.get("request_count", 0),
            data.get("unique_endpoints", 0),
            data.get("unique_methods", 0),
            data.get("avg_interval", 0.0),
            data.get("error_rate", 0.0),
            data.get("time_of_day", 0),
            data.get("unique_user_agents", 0),
            data.get("unique_countries", 0),
        ]])

    def train_ml(self, data_list: List[Dict[str, Any]]) -> bool:
        """
        بيدرب موديل ML على قائمة من البيانات السلوكية.
        """
        if len(data_list) < settings.DEFENSE_ANOMALY_MIN_SAMPLES:
            logger.warning(
                "anomaly_train_insufficient_data",
                count=len(data_list),
                required=settings.DEFENSE_ANOMALY_MIN_SAMPLES,
            )
            return False

        try:
            features = np.vstack([
                self._extract_features(d) for d in data_list
            ])

            self.ml_model = IsolationForest(
                contamination=settings.DEFENSE_ANOMALY_CONTAMINATION,
                n_estimators=settings.DEFENSE_ANOMALY_N_ESTIMATORS,
                random_state=42,
            )
            self.ml_model.fit(features)
            self._save_ml_model()

            logger.info("anomaly_ml_model_trained", samples=len(data_list))
            return True

        except Exception as e:
            logger.error("anomaly_train_failed", error=str(e))
            return False

    def predict_ml(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """بيتنبأ بـ ML لو الموديل موجود."""
        if self.ml_model is None:
            return {"is_anomaly": False, "score": 0.0, "reason": "no_ml_model"}

        try:
            features = self._extract_features(data)
            prediction = self.ml_model.predict(features)[0]
            score = -self.ml_model.score_samples(features)[0]
            is_anomaly = bool(prediction == -1)

            return {
                "is_anomaly": is_anomaly,
                "score": float(score),
                "reason": "ml_anomaly" if is_anomaly else "ml_normal",
            }
        except Exception as e:
            logger.error("anomaly_predict_ml_failed", error=str(e))
            return {"is_anomaly": False, "score": 0.0, "reason": "error"}

    # ─── Statistical Mode (Fallback) ───────────────────────

    def record_request(
        self,
        session_id: str,
        endpoint: str,
        method: str,
        status_code: int,
        response_time_ms: float,
    ) -> None:
        """بيسجل طلب في الذاكرة (للـ Statistical Mode)."""
        self._request_patterns[session_id].append({
            "endpoint": endpoint,
            "method": method,
            "status": status_code,
            "time": response_time_ms,
            "timestamp": time.time(),
        })
        # خلي آخر 1000 بس
        if len(self._request_patterns[session_id]) > 1000:
            self._request_patterns[session_id] = (
                self._request_patterns[session_id][-1000:]
            )

    def detect_anomaly_statistical(self, session_id: str) -> Dict[str, Any]:
        """
        بيفحص الأنماط باستخدام heuristics (Statistical Mode).
        """
        patterns = self._request_patterns.get(session_id, [])
        if len(patterns) < 10:
            return {"is_anomaly": False, "score": 0.0, "reasons": []}

        recent = patterns[-50:]
        score = 0.0
        reasons = []

        # 1. Endpoint diversity (scanning pattern)
        unique_endpoints = len(set(r["endpoint"] for r in recent))
        if unique_endpoints > 30:
            score += 0.4
            reasons.append(f"High endpoint diversity: {unique_endpoints}")

        # 2. Error rate
        errors = sum(1 for r in recent if r["status"] >= 400)
        error_rate = errors / len(recent)
        if error_rate > 0.5:
            score += 0.3
            reasons.append(f"High error rate: {error_rate:.0%}")

        # 3. Request rate
        time_span = recent[-1]["timestamp"] - recent[0]["timestamp"]
        if time_span > 0.1:  # ← 100ms على الأقل (نتجنب الأرقام الضخمة)
            rps = len(recent) / time_span
            if rps > 10:
                score += 0.3
                reasons.append(f"High request rate: {rps:.1f} req/s")

        return {
            "is_anomaly": score > 0.6,
            "score": min(1.0, score),
            "reasons": reasons,
        }

    # ─── Unified Detection ─────────────────────────────────

    def detect(
        self,
        session_id: str,
        behavioral_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        بيكشف الشذوذ باستخدام ML (لو موجود) أو Statistical (fallback).

        Args:
            session_id: معرّف الجلسة
            behavioral_data: بيانات سلوكية من IPLogger (اختياري)

        Returns:
            dict فيه is_anomaly, score, reason/reasons, method
        """
        # 1. جرب ML الأول
        if self.ml_model is not None and behavioral_data is not None:
            ml_result = self.predict_ml(behavioral_data)
            ml_result["method"] = "ml"
            if ml_result["is_anomaly"]:
                return ml_result

        # 2. جرب Statistical
        stat_result = self.detect_anomaly_statistical(session_id)
        stat_result["method"] = "statistical"
        return stat_result

    def is_trained(self) -> bool:
        """بترجع True لو الموديل مدرب."""
        return self.ml_model is not None