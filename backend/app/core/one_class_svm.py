"""
One-Class SVM — Anomaly detection using One-Class SVM.

بيوفر:
- Training on normal data only (semi-supervised)
- Calibration split for accurate threshold
- Prediction (normal / anomaly)
- Anomaly scoring (distance from decision boundary)
- Adaptive threshold (nu-based)
- Model persistence (save/load)
- Batch prediction
- Model statistics
- Hyperparameter tuning helpers

الفكرة:
- One-Class SVM بيتدرب على "السلوك الطبيعي" بس
- أي حاجة برة النطاق = anomaly
- Calibration split بيضمن FP rate قريبة من nu

الاستخدام:
- anomaly_detection.py
- ensemble_anomaly.py
- user_baseline.py
- session_analyzer.py
"""

import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
import structlog
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler

logger = structlog.get_logger()


class OneClassSVMDetector:
    """
    One-Class SVM Anomaly Detector.

    الفكرة:
    - StandardScaler للـ features
    - Calibration split (20%) لحساب threshold دقيق
    - One-Class SVM للـ anomaly detection
    - Anomaly score = threshold - decision
    """

    # ─── Config ────────────────────────────────────────────
    DEFAULT_KERNEL = "rbf"
    DEFAULT_NU = 0.05
    DEFAULT_GAMMA = "scale"
    MODEL_DIR = "storage/models"
    MODEL_NAME = "one_class_svm.pkl"

    # ─── Calibration ──────────────────────────────────────
    DEFAULT_CALIBRATION_RATIO = 0.2
    MIN_SAMPLES_FOR_CALIBRATION = 100

    # ─── Thresholds ────────────────────────────────────────
    DEFAULT_ANOMALY_THRESHOLD = 0.0

    # ─── State ────────────────────────────────────────────
    _model: Optional[OneClassSVM] = None
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
        """بيرجع الـ adaptive threshold."""
        return cls._threshold

    # ═══════════════════════════════════════════════════════
    #  Training (with Calibration Split)
    # ═══════════════════════════════════════════════════════

    @classmethod
    def train(
        cls,
        X: np.ndarray,
        *,
        kernel: str = DEFAULT_KERNEL,
        nu: float = DEFAULT_NU,
        gamma: str = DEFAULT_GAMMA,
        scale_features: bool = True,
        calibration_ratio: float = DEFAULT_CALIBRATION_RATIO,
        use_calibration: bool = True,
        random_seed: int = 42,
    ) -> Dict[str, Any]:
        """
        بيدرب الموديل على بيانات "طبيعية".

        Args:
            X: numpy array (n_samples, n_features)
            kernel: rbf, linear, poly, sigmoid
            nu: نسبة outliers المتوقعة (0 < nu <= 1)
            gamma: kernel coefficient
            scale_features: يعمل StandardScaler؟
            calibration_ratio: نسبة البيانات للـ calibration
            use_calibration: يستخدم calibration split؟
            random_seed: بذرة الـ split

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

            X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

            start_time = time.time()
            n_total = X.shape[0]

            # ─── Calibration Split ───
            if use_calibration and n_total >= cls.MIN_SAMPLES_FOR_CALIBRATION:
                n_cal = max(int(n_total * calibration_ratio), 30)
                n_train = n_total - n_cal

                rng = np.random.RandomState(random_seed)
                idx = rng.permutation(n_total)

                X_train = X[idx[:n_train]]
                X_cal = X[idx[n_train:]]
                used_calibration = True
            else:
                X_train = X
                X_cal = X
                n_cal = 0
                n_train = n_total
                used_calibration = False

            # ─── Scaling ───
            scaler = None
            X_train_s = X_train
            X_cal_s = X_cal
            X_full_s = X

            if scale_features:
                scaler = StandardScaler()
                X_train_s = scaler.fit_transform(X_train)
                X_cal_s = scaler.transform(X_cal)
                X_full_s = scaler.transform(X)

            # ─── Train SVM ───
            model = OneClassSVM(
                kernel=kernel,
                nu=nu,
                gamma=gamma,
            )
            model.fit(X_train_s)

            # ─── Compute adaptive threshold ───
            if used_calibration:
                # Use calibration set (unbiased estimate for new samples)
                cal_scores = model.decision_function(X_cal_s)
                threshold = float(np.percentile(cal_scores, nu * 100))
            else:
                # Fallback: percentile from training scores
                train_scores = model.decision_function(X_train_s)
                threshold = float(np.percentile(train_scores, nu * 100))

            # ─── Compute stats on full data ───
            full_scores = model.decision_function(X_full_s)
            predictions = np.where(full_scores < threshold, -1, 1)

            n_normal = int(np.sum(predictions == 1))
            n_anomaly = int(np.sum(predictions == -1))
            anomaly_ratio = n_anomaly / len(predictions)

            training_time = time.time() - start_time

            # ─── Save as singleton ───
            cls._model = model
            cls._scaler = scaler
            cls._is_trained = True
            cls._threshold = threshold
            cls._training_stats = {
                "n_samples": int(n_total),
                "n_features": int(X.shape[1]),
                "n_train": int(n_train),
                "n_calibration": int(n_cal),
                "used_calibration": bool(used_calibration),
                "kernel": kernel,
                "nu": nu,
                "gamma": gamma,
                "n_support_vectors": int(model.support_vectors_.shape[0]),
                "n_normal": n_normal,
                "n_anomaly": n_anomaly,
                "anomaly_ratio": float(anomaly_ratio),
                "decision_min": float(np.min(full_scores)),
                "decision_max": float(np.max(full_scores)),
                "decision_mean": float(np.mean(full_scores)),
                "threshold": float(threshold),
                "training_time_sec": round(training_time, 3),
                "trained_at": time.time(),
            }

            logger.info(
                "one_class_svm_trained",
                n_samples=n_total,
                n_train=n_train,
                n_cal=n_cal,
                n_features=X.shape[1],
                anomaly_ratio=round(anomaly_ratio, 3),
                threshold=round(threshold, 4),
                used_calibration=used_calibration,
                training_time_sec=round(training_time, 3),
            )

            return {
                "success": True,
                **cls._training_stats,
            }

        except Exception as e:
            logger.error("one_class_svm_train_failed", error=str(e))
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
        """بيتنبأ بـ normal/anomaly."""
        if not cls.is_trained():
            return {
                "success": False,
                "error": "model_not_trained",
                "is_anomaly": False,
                "anomaly_score": 0.0,
            }

        try:
            X = np.asarray(X, dtype=np.float64)

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

            decision = cls._model.decision_function(X)

            predictions = np.where(
                decision < cls._threshold, -1, 1
            )
            anomaly_scores = cls._threshold - decision

            if single:
                return {
                    "success": True,
                    "is_anomaly": bool(predictions[0] == -1),
                    "anomaly_score": float(anomaly_scores[0]),
                    "decision_score": float(decision[0]),
                    "threshold": float(cls._threshold),
                    "prediction": int(predictions[0]),
                }

            return {
                "success": True,
                "predictions": [int(p) for p in predictions],
                "anomaly_scores": [float(s) for s in anomaly_scores],
                "decision_scores": [float(d) for d in decision],
                "threshold": float(cls._threshold),
                "n_anomalies": int(np.sum(predictions == -1)),
                "n_normal": int(np.sum(predictions == 1)),
            }

        except Exception as e:
            logger.error("one_class_svm_predict_failed", error=str(e))
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
                })

            return results

        except Exception as e:
            logger.error("one_class_svm_batch_predict_failed", error=str(e))
            return []

    # ═══════════════════════════════════════════════════════
    #  Anomaly Detection
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
                "version": "1.2",
            }

            joblib.dump(payload, path)

            logger.info("one_class_svm_saved", path=path)

            return {
                "success": True,
                "path": path,
                "size_bytes": os.path.getsize(path),
            }

        except Exception as e:
            logger.error("one_class_svm_save_failed", error=str(e))
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

            logger.info("one_class_svm_loaded", path=path)

            return {
                "success": True,
                "path": path,
                "trained_at": cls._training_stats.get("trained_at"),
                "threshold": cls._threshold,
            }

        except Exception as e:
            logger.error("one_class_svm_load_failed", error=str(e))
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
            logger.error("one_class_svm_delete_failed", error=str(e))
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
        logger.info("one_class_svm_reset")


# ─── Standalone functions ─────────────────────────────

def train_detector(
    X: np.ndarray,
    **kwargs,
) -> Dict[str, Any]:
    """Shortcut for OneClassSVMDetector.train."""
    return OneClassSVMDetector.train(X, **kwargs)


def predict_anomaly(X: np.ndarray) -> Dict[str, Any]:
    """Shortcut for OneClassSVMDetector.predict."""
    return OneClassSVMDetector.predict(X)


def is_anomaly(X: np.ndarray, threshold: float = 0.0) -> bool:
    """Shortcut for OneClassSVMDetector.is_anomaly."""
    return OneClassSVMDetector.is_anomaly(X, threshold)