"""
LOF Detector — Anomaly detection using Local Outlier Factor.

بيوفر:
- Local density-based anomaly detection
- Novelty detection (predict on new data)
- LOF scoring (higher = more anomalous)
- Model persistence (save/load)
- Batch prediction
- Model statistics
- Hyperparameter tuning (n_neighbors, contamination)

الفكرة:
- LOF بيقيس كثافة الجيران المحليين
- LOF ~ 1   → نقطة عادية
- LOF > 1   → outlier (كثافتها أقل من جيرانها)
- LOF >> 1  → outlier قوي

الفرق عن One-Class SVM:
- SVM: global boundary
- LOF: local density comparison
- LOF أفضل لـ: anomalies داخل clusters

الاستخدام:
- anomaly_detection.py
- ensemble_anomaly.py
- user_baseline.py
"""

import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import numpy as np
import structlog
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler

logger = structlog.get_logger()


class LOFDetector:
    """
    Local Outlier Factor Anomaly Detector.

    الفكرة:
    - StandardScaler للـ features
    - LOF مع novelty=True (للـ prediction على new data)
    - lof_score = -decision - offset_   (≈1 = normal, >1 = anomaly)
    """

    # ─── Config ────────────────────────────────────────────
    DEFAULT_N_NEIGHBORS = 20
    DEFAULT_CONTAMINATION = "auto"
    DEFAULT_METRIC = "minkowski"
    MODEL_DIR = "storage/models"
    MODEL_NAME = "lof_detector.pkl"

    # ─── Thresholds ────────────────────────────────────────
    # decision_function > threshold = normal, < threshold = anomaly
    DEFAULT_ANOMALY_THRESHOLD = 0.0

    # ─── State ────────────────────────────────────────────
    _model: Optional[LocalOutlierFactor] = None
    _scaler: Optional[StandardScaler] = None
    _is_trained: bool = False
    _training_stats: Dict[str, Any] = {}
    _metadata: Dict[str, Any] = {}
    _threshold: float = 0.0

    # ═══════════════════════════════════════════════════════
    #  Internal Helpers
    # ═══════════════════════════════════════════════════════

    @classmethod
    def _ensure_dir(cls) -> None:
        """بيتأكد إن مجلد الموديلات موجود."""
        Path(cls.MODEL_DIR).mkdir(parents=True, exist_ok=True)

    @classmethod
    def _model_path(cls, name: Optional[str] = None) -> str:
        """بيرجع مسار ملف الموديل."""
        return os.path.join(cls.MODEL_DIR, name or cls.MODEL_NAME)

    @classmethod
    def is_trained(cls) -> bool:
        """بيتحقق لو الموديل متدرب."""
        return cls._is_trained and cls._model is not None

    @classmethod
    def get_threshold(cls) -> float:
        """بيرجع الـ threshold."""
        return cls._threshold

    # ═══════════════════════════════════════════════════════
    #  Training
    # ═══════════════════════════════════════════════════════

    @classmethod
    def train(
        cls,
        X: np.ndarray,
        *,
        n_neighbors: int = DEFAULT_N_NEIGHBORS,
        contamination: Any = DEFAULT_CONTAMINATION,
        metric: str = DEFAULT_METRIC,
        scale_features: bool = True,
    ) -> Dict[str, Any]:
        """
        بيدرب الموديل على بيانات "طبيعية".

        ملاحظة مهمة:
        - LOF في sklearn محتاج `novelty=True` للـ prediction على new data
        - مع `novelty=False` (default)، الـ fit_predict بس بيشتغل على training data
        - إحنا نستخدم `novelty=True` عشان نقدر نعمل predict لاحقاً

        Args:
            X: numpy array (n_samples, n_features)
            n_neighbors: عدد الجيران للـ LOF
            contamination: نسبة الـ outliers المتوقعة
                          "auto" | float in (0, 0.5]
            metric: distance metric
            scale_features: يعمل StandardScaler؟

        Returns:
            dict فيه training stats
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

            # LOF محتاج n_neighbors < n_samples
            if n_neighbors >= X.shape[0]:
                n_neighbors = max(2, X.shape[0] - 1)
                logger.warning(
                    "lof_n_neighbors_adjusted",
                    new_value=n_neighbors,
                    reason="must_be_less_than_n_samples",
                )

            # عالج NaN/Inf
            X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

            start_time = time.time()

            # 1. Scaling
            scaler = None
            X_scaled = X
            if scale_features:
                scaler = StandardScaler()
                X_scaled = scaler.fit_transform(X)

            # 2. Train LOF
            # مهم: novelty=True عشان predict يشتغل على new data
            model = LocalOutlierFactor(
                n_neighbors=n_neighbors,
                contamination=contamination,
                metric=metric,
                novelty=True,
            )
            model.fit(X_scaled)

            # 3. Compute threshold من training data
            # decision_function: positive = inlier, negative = outlier
            # نستخدم percentile من decision scores
            decision_scores = model.decision_function(X_scaled)

            threshold = float(np.percentile(decision_scores, 5.0))

            # 4. Predictions
            predictions = np.where(
                decision_scores < threshold, -1, 1
            )

            n_normal = int(np.sum(predictions == 1))
            n_anomaly = int(np.sum(predictions == -1))
            anomaly_ratio = n_anomaly / len(predictions)

            training_time = time.time() - start_time

            # 5. Save as singleton
            cls._model = model
            cls._scaler = scaler
            cls._is_trained = True
            cls._threshold = threshold
            cls._training_stats = {
                "n_samples": int(X.shape[0]),
                "n_features": int(X.shape[1]),
                "n_neighbors": int(n_neighbors),
                "contamination": (
                    contamination
                    if isinstance(contamination, str)
                    else float(contamination)
                ),
                "metric": metric,
                "n_normal": n_normal,
                "n_anomaly": n_anomaly,
                "anomaly_ratio": float(anomaly_ratio),
                "decision_min": float(np.min(decision_scores)),
                "decision_max": float(np.max(decision_scores)),
                "decision_mean": float(np.mean(decision_scores)),
                "threshold": float(threshold),
                "offset": float(model.offset_),
                "training_time_sec": round(training_time, 3),
                "trained_at": time.time(),
            }

            logger.info(
                "lof_trained",
                n_samples=X.shape[0],
                n_features=X.shape[1],
                n_neighbors=n_neighbors,
                anomaly_ratio=round(anomaly_ratio, 3),
                threshold=round(threshold, 4),
                training_time_sec=round(training_time, 3),
            )

            return {
                "success": True,
                **cls._training_stats,
            }

        except Exception as e:
            logger.error("lof_train_failed", error=str(e))
            return {
                "success": False,
                "error": str(e),
            }

    # ═══════════════════════════════════════════════════════
    #  Prediction
    # ═══════════════════════════════════════════════════════

    @classmethod
    def predict(
        cls,
        X: np.ndarray,
    ) -> Dict[str, Any]:
        """
        بيتنبأ بـ normal/anomaly.

        Args:
            X: numpy array (n_samples, n_features) أو (n_features,)

        Returns:
            dict فيه:
            - is_anomaly: bool (للـ single)
            - anomaly_score: float (أعلى = أكثر شذوذاً)
            - lof_score: float (≈1.0 = normal, >1.0 = anomaly)
            - decision_score: float
        """
        if not cls.is_trained():
            return {
                "success": False,
                "error": "model_not_trained",
                "is_anomaly": False,
                "anomaly_score": 0.0,
            }

        try:
            X = np.asarray(X, dtype=np.float64)

            # ─── Single sample detection ───
            if X.ndim == 1:
                X = X.reshape(1, -1)
                single = True
            elif X.ndim == 2 and X.shape[0] == 1:
                single = True
            else:
                single = False

            X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

            if cls._scaler is not None:
                X = cls._scaler.transform(X)

            # predict (decision function)
            decision = cls._model.decision_function(X)

            # predictions
            predictions = np.where(
                decision < cls._threshold, -1, 1
            )

            # anomaly_score = threshold - decision
            anomaly_scores = cls._threshold - decision

            # LOF score (raw)
            # من sklearn docs:
            #   score_samples(X) = -LOF(X)   (سالب LOF)
            #   decision_function(X) = score_samples(X) - offset_
            # إذاً: decision = -LOF - offset_
            # إذاً: LOF = -decision - offset_
            lof_scores = -decision - cls._model.offset_

            if single:
                return {
                    "success": True,
                    "is_anomaly": bool(predictions[0] == -1),
                    "anomaly_score": float(anomaly_scores[0]),
                    "decision_score": float(decision[0]),
                    "lof_score": float(lof_scores[0]),
                    "threshold": float(cls._threshold),
                    "prediction": int(predictions[0]),
                }

            return {
                "success": True,
                "predictions": [int(p) for p in predictions],
                "anomaly_scores": [float(s) for s in anomaly_scores],
                "decision_scores": [float(d) for d in decision],
                "lof_scores": [float(s) for s in lof_scores],
                "threshold": float(cls._threshold),
                "n_anomalies": int(np.sum(predictions == -1)),
                "n_normal": int(np.sum(predictions == 1)),
            }

        except Exception as e:
            logger.error("lof_predict_failed", error=str(e))
            return {
                "success": False,
                "error": str(e),
                "is_anomaly": False,
                "anomaly_score": 0.0,
            }

    @classmethod
    def predict_batch(
        cls,
        X: np.ndarray,
        *,
        return_only_anomalies: bool = False,
    ) -> List[Dict[str, Any]]:
        """بيتنبأ لمجموعة samples."""
        if not cls.is_trained():
            return []

        try:
            X = np.asarray(X, dtype=np.float64)
            if X.ndim == 1:
                X = X.reshape(1, -1)

            X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

            if cls._scaler is not None:
                X = cls._scaler.transform(X)

            decision = cls._model.decision_function(X)

            predictions = np.where(
                decision < cls._threshold, -1, 1
            )
            anomaly_scores = cls._threshold - decision
            lof_scores = -decision - cls._model.offset_

            results = []
            for i in range(len(predictions)):
                is_anom = bool(predictions[i] == -1)
                if return_only_anomalies and not is_anom:
                    continue

                results.append({
                    "index": i,
                    "is_anomaly": is_anom,
                    "anomaly_score": float(anomaly_scores[i]),
                    "decision_score": float(decision[i]),
                    "lof_score": float(lof_scores[i]),
                })

            return results

        except Exception as e:
            logger.error("lof_batch_predict_failed", error=str(e))
            return []

    # ═══════════════════════════════════════════════════════
    #  Anomaly Detection Helpers
    # ═══════════════════════════════════════════════════════

    @classmethod
    def is_anomaly(
        cls,
        X: np.ndarray,
        threshold: float = DEFAULT_ANOMALY_THRESHOLD,
    ) -> bool:
        """بيتحقق لو sample واحدة anomaly."""
        result = cls.predict(X)

        if not result.get("success"):
            return False

        if result.get("is_anomaly", False):
            return True

        return result.get("anomaly_score", 0.0) > threshold

    @classmethod
    def get_anomaly_score(cls, X: np.ndarray) -> float:
        """بيرجع anomaly score لـ sample."""
        result = cls.predict(X)
        if not result.get("success"):
            return 0.0
        return result.get("anomaly_score", 0.0)

    @classmethod
    def get_lof_score(cls, X: np.ndarray) -> float:
        """بيرجع LOF raw score لـ sample."""
        result = cls.predict(X)
        if not result.get("success"):
            return 1.0
        return result.get("lof_score", 1.0)

    # ═══════════════════════════════════════════════════════
    #  Persistence
    # ═══════════════════════════════════════════════════════

    @classmethod
    def save(cls, name: Optional[str] = None) -> Dict[str, Any]:
        """بيحفظ الموديل على disk."""
        if not cls.is_trained():
            return {
                "success": False,
                "error": "model_not_trained",
            }

        try:
            cls._ensure_dir()
            path = cls._model_path(name)

            payload = {
                "model": cls._model,
                "scaler": cls._scaler,
                "training_stats": cls._training_stats,
                "metadata": cls._metadata,
                "threshold": cls._threshold,
                "saved_at": time.time(),
                "version": "1.0",
            }

            joblib.dump(payload, path)

            logger.info("lof_saved", path=path)

            return {
                "success": True,
                "path": path,
                "size_bytes": os.path.getsize(path),
            }

        except Exception as e:
            logger.error("lof_save_failed", error=str(e))
            return {
                "success": False,
                "error": str(e),
            }

    @classmethod
    def load(cls, name: Optional[str] = None) -> Dict[str, Any]:
        """بيحمّل الموديل من disk."""
        try:
            path = cls._model_path(name)

            if not os.path.exists(path):
                return {
                    "success": False,
                    "error": "file_not_found",
                    "path": path,
                }

            payload = joblib.load(path)

            cls._model = payload.get("model")
            cls._scaler = payload.get("scaler")
            cls._training_stats = payload.get("training_stats", {})
            cls._metadata = payload.get("metadata", {})
            cls._threshold = payload.get("threshold", 0.0)
            cls._is_trained = cls._model is not None

            logger.info("lof_loaded", path=path)

            return {
                "success": True,
                "path": path,
                "trained_at": cls._training_stats.get("trained_at"),
                "threshold": cls._threshold,
            }

        except Exception as e:
            logger.error("lof_load_failed", error=str(e))
            return {
                "success": False,
                "error": str(e),
            }

    @classmethod
    def delete_model(cls, name: Optional[str] = None) -> bool:
        """بيمسح ملف الموديل."""
        try:
            path = cls._model_path(name)
            if os.path.exists(path):
                os.remove(path)
                return True
            return False
        except Exception as e:
            logger.error("lof_delete_failed", error=str(e))
            return False

    # ═══════════════════════════════════════════════════════
    #  Info
    # ═══════════════════════════════════════════════════════

    @classmethod
    def get_stats(cls) -> Dict[str, Any]:
        """بيرجع إحصائيات الموديل."""
        return {
            "is_trained": cls.is_trained(),
            "threshold": cls._threshold,
            "training_stats": dict(cls._training_stats),
            "metadata": dict(cls._metadata),
        }

    @classmethod
    def set_metadata(cls, key: str, value: Any) -> None:
        """بيحدد metadata."""
        cls._metadata[key] = value

    @classmethod
    def get_metadata(cls) -> Dict[str, Any]:
        """بيرجع الـ metadata."""
        return dict(cls._metadata)

    # ═══════════════════════════════════════════════════════
    #  Reset
    # ═══════════════════════════════════════════════════════

    @classmethod
    def reset(cls) -> None:
        """بيمسح الموديل من الـ memory."""
        cls._model = None
        cls._scaler = None
        cls._is_trained = False
        cls._training_stats = {}
        cls._metadata = {}
        cls._threshold = 0.0
        logger.info("lof_reset")


# ─── Standalone functions ─────────────────────────────

def train_detector(
    X: np.ndarray,
    **kwargs,
) -> Dict[str, Any]:
    """Shortcut for LOFDetector.train."""
    return LOFDetector.train(X, **kwargs)


def predict_anomaly(X: np.ndarray) -> Dict[str, Any]:
    """Shortcut for LOFDetector.predict."""
    return LOFDetector.predict(X)


def is_anomaly(X: np.ndarray, threshold: float = 0.0) -> bool:
    """Shortcut for LOFDetector.is_anomaly."""
    return LOFDetector.is_anomaly(X, threshold)


def get_lof_score(X: np.ndarray) -> float:
    """Shortcut for LOFDetector.get_lof_score."""
    return LOFDetector.get_lof_score(X)