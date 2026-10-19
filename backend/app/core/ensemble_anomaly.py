"""
Ensemble Anomaly — Multi-detector anomaly ensemble.

بيوفر:
- Combines multiple anomaly detectors
- Voting strategies: majority, weighted, any, all
- Detector weighting based on performance
- Isolation Forest detector (built-in)
- Model persistence (save/load)
- Batch prediction
- Confidence scoring
- Integration with One-Class SVM + LOF

الفكرة:
- كل detector عنده نقاط قوة وضعف
- الدمج بيقلل FP و FN
- Voting strategies مختلفة حسب الحالة

الاستخدام:
- anomaly_detection.py
- user_baseline.py
- session_analyzer.py
- attack_chain.py
"""

import os
import time
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
import structlog
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

logger = structlog.get_logger()


class VotingStrategy(str, Enum):
    """استراتيجيات التصويت."""
    MAJORITY = "majority"       # >50% يقولوا anomaly
    ANY = "any"                 # أي detector يقول anomaly
    ALL = "all"                 # كل detectors تقول anomaly
    WEIGHTED = "weighted"       # متوسط موزون
    AVERAGE = "average"         # متوسط بسيط


class EnsembleAnomalyDetector:
    """
    Ensemble Anomaly Detector.

    الفكرة:
    - بيجمع 3 detectors:
      * One-Class SVM
      * LOF
      * Isolation Forest (built-in)
    - Voting strategy للدمج
    - Weights للتحكم في تأثير كل detector
    """

    # ─── Config ────────────────────────────────────────────
    MODEL_DIR = "storage/models"
    MODEL_NAME = "ensemble_anomaly.pkl"

    # ─── Voting ───────────────────────────────────────────
    DEFAULT_STRATEGY = VotingStrategy.MAJORITY

    # ─── Detector Weights (default) ───────────────────────
    DEFAULT_WEIGHTS = {
        "svm": 1.0,
        "lof": 1.0,
        "iforest": 1.0,
    }

    # ─── Thresholds ────────────────────────────────────────
    DEFAULT_ANOMALY_THRESHOLD = 0.5    # للـ weighted/average score

    # ─── State ────────────────────────────────────────────
    _iforest_model: Optional[IsolationForest] = None
    _iforest_scaler: Optional[StandardScaler] = None
    _iforest_trained: bool = False
    _iforest_threshold: float = 0.0

    _weights: Dict[str, float] = {}
    _strategy: VotingStrategy = DEFAULT_STRATEGY
    _training_stats: Dict[str, Any] = {}
    _metadata: Dict[str, Any] = {}

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
    def set_weights(cls, weights: Dict[str, float]) -> None:
        """بيحدد أوزان الـ detectors."""
        cls._weights = {**cls.DEFAULT_WEIGHTS, **weights}

    @classmethod
    def set_strategy(cls, strategy: VotingStrategy) -> None:
        """بيحدد استراتيجية التصويت."""
        if isinstance(strategy, str):
            strategy = VotingStrategy(strategy)
        cls._strategy = strategy

    @classmethod
    def get_weights(cls) -> Dict[str, float]:
        """بيرجع الأوزان الحالية."""
        return dict(cls._weights or cls.DEFAULT_WEIGHTS)

    @classmethod
    def get_strategy(cls) -> str:
        """بيرجع الاستراتيجية الحالية."""
        return cls._strategy.value

    # ═══════════════════════════════════════════════════════
    #  Isolation Forest (Built-in)
    # ═══════════════════════════════════════════════════════

    @classmethod
    def _train_iforest(
        cls,
        X: np.ndarray,
        *,
        n_estimators: int = 100,
        contamination: float = 0.05,
        scale_features: bool = True,
    ) -> Dict[str, Any]:
        """بيدرب Isolation Forest داخلياً."""
        try:
            scaler = None
            X_scaled = X
            if scale_features:
                scaler = StandardScaler()
                X_scaled = scaler.fit_transform(X)

            model = IsolationForest(
                n_estimators=n_estimators,
                contamination=contamination,
                random_state=42,
                n_jobs=-1,
            )
            model.fit(X_scaled)

            # compute threshold
            decision_scores = model.decision_function(X_scaled)
            threshold = float(np.percentile(decision_scores, 5.0))

            # compute anomaly_ratio on training data
            preds = np.where(decision_scores < threshold, -1, 1)
            n_anomaly = int(np.sum(preds == -1))
            anomaly_ratio = n_anomaly / len(preds) if len(preds) > 0 else 0.0

            cls._iforest_model = model
            cls._iforest_scaler = scaler
            cls._iforest_trained = True
            cls._iforest_threshold = threshold

            return {
                "success": True,
                "n_estimators": n_estimators,
                "contamination": contamination,
                "threshold": threshold,
                "anomaly_ratio": float(anomaly_ratio),
                "n_anomaly": n_anomaly,
                "n_normal": int(len(preds) - n_anomaly),
            }
        except Exception as e:
            logger.error("iforest_train_failed", error=str(e))
            return {"success": False, "error": str(e)}

    @classmethod
    def _predict_iforest(cls, X: np.ndarray) -> Dict[str, Any]:
        """بيتنبأ باستخدام Isolation Forest."""
        if not cls._iforest_trained:
            return {
                "success": False,
                "error": "iforest_not_trained",
            }

        try:
            X = np.asarray(X, dtype=np.float64)
            if X.ndim == 1:
                X = X.reshape(1, -1)

            X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

            if cls._iforest_scaler is not None:
                X = cls._iforest_scaler.transform(X)

            decision = cls._iforest_model.decision_function(X)
            predictions = np.where(
                decision < cls._iforest_threshold, -1, 1
            )
            anomaly_scores = cls._iforest_threshold - decision

            return {
                "success": True,
                "predictions": [int(p) for p in predictions],
                "anomaly_scores": [float(s) for s in anomaly_scores],
                "is_anomaly": bool(predictions[0] == -1),
                "anomaly_score": float(anomaly_scores[0]),
            }
        except Exception as e:
            logger.error("iforest_predict_failed", error=str(e))
            return {"success": False, "error": str(e)}

    # ═══════════════════════════════════════════════════════
    #  Training
    # ═══════════════════════════════════════════════════════

    @classmethod
    def train(
        cls,
        X: np.ndarray,
        *,
        train_svm: bool = True,
        train_lof: bool = True,
        train_iforest: bool = True,
        nu: float = 0.05,
        n_neighbors: int = 20,
        n_estimators: int = 100,
        contamination: float = 0.05,
        strategy: VotingStrategy = VotingStrategy.MAJORITY,
        weights: Optional[Dict[str, float]] = None,
    ) -> Dict[str, Any]:
        """
        بيدرب كل الـ detectors ويجمعهم.

        Args:
            X: numpy array (n_samples, n_features)
            train_svm: يدرب SVM؟
            train_lof: يدرب LOF؟
            train_iforest: يدرب Isolation Forest؟
            nu: nu للـ SVM
            n_neighbors: جيران LOF
            n_estimators: عدد الأشجار للـ IForest
            contamination: نسبة outliers المتوقعة
            strategy: استراتيجية التصويت
            weights: أوزان الـ detectors

        Returns:
            dict فيه training stats
        """
        try:
            X = np.asarray(X, dtype=np.float64)
            if X.ndim == 1:
                X = X.reshape(-1, 1)

            if X.shape[0] < 20:
                return {
                    "success": False,
                    "error": "insufficient_samples",
                    "min_required": 20,
                    "got": int(X.shape[0]),
                }

            X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

            start_time = time.time()

            # set strategy & weights
            cls.set_strategy(strategy)
            if weights:
                cls.set_weights(weights)

            results: Dict[str, Any] = {}

            # ─── 1. Train SVM ───
            if train_svm:
                from app.core.one_class_svm import OneClassSVMDetector
                svm_result = OneClassSVMDetector.train(
                    X, nu=nu, use_calibration=True,
                )
                results["svm"] = {
                    "success": svm_result.get("success", False),
                    "anomaly_ratio": svm_result.get("anomaly_ratio", 0.0),
                    "threshold": svm_result.get("threshold", 0.0),
                }

            # ─── 2. Train LOF ───
            if train_lof:
                from app.core.lof_detector import LOFDetector
                lof_result = LOFDetector.train(
                    X, n_neighbors=n_neighbors,
                    contamination=contamination,
                )
                results["lof"] = {
                    "success": lof_result.get("success", False),
                    "anomaly_ratio": lof_result.get("anomaly_ratio", 0.0),
                    "threshold": lof_result.get("threshold", 0.0),
                }

            # ─── 3. Train Isolation Forest ───
            if train_iforest:
                if_result = cls._train_iforest(
                    X,
                    n_estimators=n_estimators,
                    contamination=contamination,
                )
                results["iforest"] = if_result

            training_time = time.time() - start_time

            cls._training_stats = {
                "n_samples": int(X.shape[0]),
                "n_features": int(X.shape[1]),
                "strategy": cls._strategy.value,
                "weights": dict(cls._weights),
                "detectors": results,
                "active_detectors": [
                    k for k, v in results.items()
                    if v.get("success")
                ],
                "training_time_sec": round(training_time, 3),
                "trained_at": time.time(),
            }

            logger.info(
                "ensemble_trained",
                n_samples=X.shape[0],
                active_detectors=cls._training_stats["active_detectors"],
                strategy=cls._strategy.value,
                training_time_sec=round(training_time, 3),
            )

            return {
                "success": True,
                **cls._training_stats,
            }

        except Exception as e:
            logger.error("ensemble_train_failed", error=str(e))
            return {
                "success": False,
                "error": str(e),
            }

    # ═══════════════════════════════════════════════════════
    #  Voting / Combination
    # ═══════════════════════════════════════════════════════

    @classmethod
    def _combine_predictions(
        cls,
        detector_results: Dict[str, Dict[str, Any]],
        strategy: Optional[VotingStrategy] = None,
    ) -> Dict[str, Any]:
        """
        بيدمج نتائج الـ detectors باستخدام الاستراتيجية.
        """
        strategy = strategy or cls._strategy
        weights = cls._weights or cls.DEFAULT_WEIGHTS

        # اجمع النتايج
        votes = []
        weighted_scores = []
        total_weight = 0.0

        for name, result in detector_results.items():
            if not result.get("success", False):
                continue

            is_anom = result.get("is_anomaly", False)
            score = result.get("anomaly_score", 0.0)
            weight = weights.get(name, 1.0)

            votes.append((name, is_anom, weight))
            weighted_scores.append(score * weight)
            total_weight += weight

        if not votes:
            return {
                "is_anomaly": False,
                "confidence": 0.0,
                "combined_score": 0.0,
                "votes": {},
                "n_anomaly_votes": 0,
                "n_total_votes": 0,
            }

        # ─── VOTING ───
        n_anomaly = sum(1 for _, is_a, _ in votes if is_a)
        n_total = len(votes)
        anomaly_ratio = n_anomaly / n_total if n_total > 0 else 0.0

        if strategy == VotingStrategy.ANY:
            is_anomaly = n_anomaly >= 1
        elif strategy == VotingStrategy.ALL:
            is_anomaly = n_anomaly == n_total
        elif strategy == VotingStrategy.MAJORITY:
            is_anomaly = n_anomaly > n_total / 2
        elif strategy in (VotingStrategy.WEIGHTED, VotingStrategy.AVERAGE):
            is_anomaly = anomaly_ratio > 0.5
        else:
            is_anomaly = n_anomaly > n_total / 2

        # ─── COMBINED SCORE ───
        if strategy == VotingStrategy.WEIGHTED and total_weight > 0:
            combined_score = sum(weighted_scores) / total_weight
        else:
            combined_score = (
                sum(weighted_scores) / n_total
                if n_total > 0 else 0.0
            )

        # ─── CONFIDENCE ───
        if is_anomaly:
            confidence = anomaly_ratio
        else:
            confidence = 1.0 - anomaly_ratio

        return {
            "is_anomaly": bool(is_anomaly),
            "confidence": float(confidence),
            "combined_score": float(combined_score),
            "votes": {name: is_a for name, is_a, _ in votes},
            "n_anomaly_votes": int(n_anomaly),
            "n_total_votes": int(n_total),
        }

    # ═══════════════════════════════════════════════════════
    #  Prediction
    # ═══════════════════════════════════════════════════════

    @classmethod
    def predict(
        cls,
        X: np.ndarray,
    ) -> Dict[str, Any]:
        """بيتنبأ باستخدام الـ ensemble."""
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

            # اجمع نتائج كل detector
            detector_results: Dict[str, Dict[str, Any]] = {}

            # SVM
            try:
                from app.core.one_class_svm import OneClassSVMDetector
                if OneClassSVMDetector.is_trained():
                    svm_result = OneClassSVMDetector.predict(X)
                    if single:
                        detector_results["svm"] = {
                            "success": svm_result.get("success", False),
                            "is_anomaly": svm_result.get("is_anomaly", False),
                            "anomaly_score": svm_result.get("anomaly_score", 0.0),
                        }
                    else:
                        detector_results["svm"] = svm_result
            except Exception as e:
                logger.warning("svm_predict_in_ensemble_failed", error=str(e))

            # LOF
            try:
                from app.core.lof_detector import LOFDetector
                if LOFDetector.is_trained():
                    lof_result = LOFDetector.predict(X)
                    if single:
                        detector_results["lof"] = {
                            "success": lof_result.get("success", False),
                            "is_anomaly": lof_result.get("is_anomaly", False),
                            "anomaly_score": lof_result.get("anomaly_score", 0.0),
                        }
                    else:
                        detector_results["lof"] = lof_result
            except Exception as e:
                logger.warning("lof_predict_in_ensemble_failed", error=str(e))

            # Isolation Forest
            if cls._iforest_trained:
                if_result = cls._predict_iforest(X)
                if if_result.get("success"):
                    if single:
                        detector_results["iforest"] = {
                            "success": True,
                            "is_anomaly": if_result.get("is_anomaly", False),
                            "anomaly_score": if_result.get("anomaly_score", 0.0),
                        }
                    else:
                        detector_results["iforest"] = {
                            "success": True,
                            "predictions": if_result.get("predictions", []),
                            "anomaly_scores": if_result.get("anomaly_scores", []),
                        }

            # ─── Filter valid detectors ───
            valid_detectors = {
                k: v for k, v in detector_results.items()
                if v.get("success", False)
            }

            if not valid_detectors:
                return {
                    "success": False,
                    "error": "no_detectors_available",
                    "is_anomaly": False,
                    "confidence": 0.0,
                }

            # ─── SINGLE SAMPLE ───
            if single:
                combined = cls._combine_predictions(valid_detectors)

                return {
                    "success": True,
                    "is_anomaly": combined["is_anomaly"],
                    "confidence": combined["confidence"],
                    "combined_score": combined["combined_score"],
                    "votes": combined["votes"],
                    "n_anomaly_votes": combined["n_anomaly_votes"],
                    "n_total_votes": combined["n_total_votes"],
                    "strategy": cls._strategy.value,
                    "detector_details": {
                        k: {
                            "is_anomaly": v.get("is_anomaly"),
                            "anomaly_score": v.get("anomaly_score"),
                        }
                        for k, v in valid_detectors.items()
                    },
                }

            # ─── BATCH ───
            n_samples = X.shape[0]
            batch_results = []

            for i in range(n_samples):
                sample_results = {}
                for det_name, det_result in valid_detectors.items():
                    if det_name == "iforest":
                        sample_results[det_name] = {
                            "success": True,
                            "is_anomaly": det_result["predictions"][i] == -1,
                            "anomaly_score": det_result["anomaly_scores"][i],
                        }
                    else:
                        if "predictions" in det_result:
                            sample_results[det_name] = {
                                "success": True,
                                "is_anomaly": det_result["predictions"][i] == -1,
                                "anomaly_score": det_result["anomaly_scores"][i],
                            }
                        else:
                            sample_results[det_name] = det_result

                combined = cls._combine_predictions(sample_results)
                batch_results.append({
                    "index": i,
                    "is_anomaly": combined["is_anomaly"],
                    "confidence": combined["confidence"],
                    "combined_score": combined["combined_score"],
                    "votes": combined["votes"],
                })

            n_anomalies = sum(1 for r in batch_results if r["is_anomaly"])

            return {
                "success": True,
                "results": batch_results,
                "n_anomalies": n_anomalies,
                "n_normal": n_samples - n_anomalies,
                "n_total": n_samples,
                "strategy": cls._strategy.value,
            }

        except Exception as e:
            logger.error("ensemble_predict_failed", error=str(e))
            return {
                "success": False,
                "error": str(e),
                "is_anomaly": False,
                "confidence": 0.0,
            }

    # ═══════════════════════════════════════════════════════
    #  Helpers
    # ═══════════════════════════════════════════════════════

    @classmethod
    def is_anomaly(cls, X: np.ndarray) -> bool:
        """بيتحقق لو sample anomaly."""
        result = cls.predict(X)
        return result.get("is_anomaly", False)

    @classmethod
    def get_confidence(cls, X: np.ndarray) -> float:
        """بيرجع confidence."""
        result = cls.predict(X)
        return result.get("confidence", 0.0)

    @classmethod
    def is_ready(cls) -> bool:
        """بيتحقق لو فيه detectors متدربة."""
        try:
            from app.core.one_class_svm import OneClassSVMDetector
            from app.core.lof_detector import LOFDetector
            return (
                OneClassSVMDetector.is_trained()
                or LOFDetector.is_trained()
                or cls._iforest_trained
            )
        except Exception:
            return cls._iforest_trained

    @classmethod
    def is_trained(cls) -> bool:
        """
        Alias لـ is_ready() — للتوافق مع ModelRegistry.

        الـ ensemble يعتبر "trained" لو فيه detector واحد متدرب على الأقل.
        """
        return cls.is_ready()

    # ═══════════════════════════════════════════════════════
    #  Persistence
    # ═══════════════════════════════════════════════════════

    @classmethod
    def save(cls, name: Optional[str] = None) -> Dict[str, Any]:
        """بيحفظ الموديل على disk."""
        if not cls._iforest_trained:
            return {
                "success": False,
                "error": "iforest_not_trained",
            }

        try:
            cls._ensure_dir()
            path = cls._model_path(name)

            payload = {
                "iforest_model": cls._iforest_model,
                "iforest_scaler": cls._iforest_scaler,
                "iforest_threshold": cls._iforest_threshold,
                "weights": cls._weights,
                "strategy": cls._strategy.value,
                "training_stats": cls._training_stats,
                "metadata": cls._metadata,
                "saved_at": time.time(),
                "version": "1.0",
            }

            joblib.dump(payload, path)

            logger.info("ensemble_saved", path=path)

            return {
                "success": True,
                "path": path,
                "size_bytes": os.path.getsize(path),
            }

        except Exception as e:
            logger.error("ensemble_save_failed", error=str(e))
            return {"success": False, "error": str(e)}

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

            cls._iforest_model = payload.get("iforest_model")
            cls._iforest_scaler = payload.get("iforest_scaler")
            cls._iforest_threshold = payload.get("iforest_threshold", 0.0)
            cls._iforest_trained = cls._iforest_model is not None
            cls._weights = payload.get("weights", dict(cls.DEFAULT_WEIGHTS))
            cls._strategy = VotingStrategy(
                payload.get("strategy", VotingStrategy.MAJORITY.value)
            )
            cls._training_stats = payload.get("training_stats", {})
            cls._metadata = payload.get("metadata", {})

            logger.info("ensemble_loaded", path=path)

            return {
                "success": True,
                "path": path,
                "strategy": cls._strategy.value,
            }

        except Exception as e:
            logger.error("ensemble_load_failed", error=str(e))
            return {"success": False, "error": str(e)}

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
            logger.error("ensemble_delete_failed", error=str(e))
            return False

    # ═══════════════════════════════════════════════════════
    #  Info
    # ═══════════════════════════════════════════════════════

    @classmethod
    def get_stats(cls) -> Dict[str, Any]:
        """بيرجع إحصائيات الـ ensemble."""
        try:
            from app.core.one_class_svm import OneClassSVMDetector
            from app.core.lof_detector import LOFDetector
            svm_trained = OneClassSVMDetector.is_trained()
            lof_trained = LOFDetector.is_trained()
        except Exception:
            svm_trained = False
            lof_trained = False

        return {
            "svm_trained": svm_trained,
            "lof_trained": lof_trained,
            "iforest_trained": cls._iforest_trained,
            "strategy": cls._strategy.value,
            "weights": dict(cls._weights or cls.DEFAULT_WEIGHTS),
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
        """بيمسح كل الـ detectors من الـ memory."""
        cls._iforest_model = None
        cls._iforest_scaler = None
        cls._iforest_trained = False
        cls._iforest_threshold = 0.0
        cls._weights = {}
        cls._strategy = cls.DEFAULT_STRATEGY
        cls._training_stats = {}
        cls._metadata = {}
        logger.info("ensemble_reset")


# ─── Standalone functions ─────────────────────────────

def train_ensemble(X: np.ndarray, **kwargs) -> Dict[str, Any]:
    """Shortcut for EnsembleAnomalyDetector.train."""
    return EnsembleAnomalyDetector.train(X, **kwargs)


def predict_ensemble(X: np.ndarray) -> Dict[str, Any]:
    """Shortcut for EnsembleAnomalyDetector.predict."""
    return EnsembleAnomalyDetector.predict(X)


def is_anomaly_ensemble(X: np.ndarray) -> bool:
    """Shortcut for EnsembleAnomalyDetector.is_anomaly."""
    return EnsembleAnomalyDetector.is_anomaly(X)