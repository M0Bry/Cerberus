"""
Autoencoder — Deep learning anomaly detection using autoencoder.

بيوفر:
- Deep autoencoder (encoder + bottleneck + decoder)
- Training on normal data (reconstruction-based)
- Anomaly score = reconstruction error (MSE)
- Threshold calibration (percentile-based)
- Model persistence (save/load)
- Batch prediction
- Model statistics
- Integration with feature_extractor

الفكرة:
- Autoencoder بيتدرب على "البيانات الطبيعية" بس
- بيتعلم يعيد بناء الـ normal patterns
- لو sample جديدة شاذة → reconstruction error عالي
- مناسب لـ:
  * High-dimensional data
  * Complex non-linear patterns
  * Novel anomalies

الاستخدام:
- anomaly_detection.py
- ensemble_anomaly.py
- user_baseline.py
"""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
import structlog
from sklearn.preprocessing import StandardScaler

# TensorFlow imports (مع كتم logs)
os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")
try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers
    _TF_AVAILABLE = True
except ImportError:  # TensorFlow is optional (see requirements.txt)
    tf = None
    keras = None
    layers = None
    _TF_AVAILABLE = False


def _require_tf() -> None:
    """Raise a clear error when TensorFlow is not installed."""
    if not _TF_AVAILABLE:
        raise RuntimeError(
            "tensorflow is required for this detector but is not "
            "installed. Install it with: pip install tensorflow"
        )

logger = structlog.get_logger()


class AutoencoderDetector:
    """
    Deep Autoencoder Anomaly Detector.

    الفكرة:
    - StandardScaler للـ features
    - Autoencoder بيتعلم إعادة البناء
    - anomaly_score = reconstruction error (MSE)
    - Calibration split (20%) لحساب threshold دقيق
    """

    # ─── Config ────────────────────────────────────────────
    MODEL_DIR = "storage/models"
    MODEL_NAME = "autoencoder.keras"
    META_NAME = "autoencoder_meta.pkl"

    # ─── Architecture ─────────────────────────────────────
    DEFAULT_HIDDEN_DIMS = [64, 32]
    DEFAULT_BOTTLENECK_DIM = 8
    DEFAULT_DROPOUT = 0.1

    # ─── Training ─────────────────────────────────────────
    DEFAULT_EPOCHS = 50
    DEFAULT_BATCH_SIZE = 32
    DEFAULT_LEARNING_RATE = 1e-3
    DEFAULT_VALIDATION_SPLIT = 0.1
    DEFAULT_PATIENCE = 5
    MIN_SAMPLES = 50

    # ─── Calibration ──────────────────────────────────────
    DEFAULT_CALIBRATION_RATIO = 0.2
    MIN_SAMPLES_FOR_CALIBRATION = 200

    # ─── Threshold ────────────────────────────────────────
    DEFAULT_PERCENTILE = 95.0
    DEFAULT_ANOMALY_THRESHOLD = 0.0

    # ─── State ────────────────────────────────────────────
    _model: Optional[keras.Model] = None
    _scaler: Optional[StandardScaler] = None
    _is_trained: bool = False
    _training_stats: Dict[str, Any] = {}
    _metadata: Dict[str, Any] = {}
    _threshold: float = 0.0
    _n_features: int = 0

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
        if name:
            return os.path.join(cls.MODEL_DIR, name)
        return os.path.join(cls.MODEL_DIR, cls.MODEL_NAME)

    @classmethod
    def _meta_path(cls, name: Optional[str] = None) -> str:
        """بيرجع مسار ملف الـ metadata."""
        if name:
            base = name.rsplit(".", 1)[0]
            return os.path.join(cls.MODEL_DIR, f"{base}_meta.pkl")
        return os.path.join(cls.MODEL_DIR, cls.META_NAME)

    @classmethod
    def is_trained(cls) -> bool:
        """بيتحقق لو الموديل متدرب."""
        return cls._is_trained and cls._model is not None

    @classmethod
    def get_threshold(cls) -> float:
        """بيرجع الـ threshold."""
        return cls._threshold

    # ═══════════════════════════════════════════════════════
    #  Build Model
    # ═══════════════════════════════════════════════════════

    @classmethod
    def _build_autoencoder(
        cls,
        n_features: int,
        *,
        hidden_dims: List[int],
        bottleneck_dim: int,
        dropout: float,
    ) -> keras.Model:
        """بيبني الـ autoencoder architecture."""
        _require_tf()
        # ─── Encoder ───
        inputs = keras.Input(shape=(n_features,), name="input")
        x = inputs
        for i, dim in enumerate(hidden_dims):
            x = layers.Dense(dim, activation="relu", name=f"enc_dense_{i}")(x)
            if dropout > 0:
                x = layers.Dropout(dropout, name=f"enc_drop_{i}")(x)

        # ─── Bottleneck ───
        bottleneck = layers.Dense(
            bottleneck_dim,
            activation="relu",
            name="bottleneck",
        )(x)

        # ─── Decoder ───
        x = bottleneck
        for i, dim in enumerate(reversed(hidden_dims)):
            x = layers.Dense(dim, activation="relu", name=f"dec_dense_{i}")(x)
            if dropout > 0:
                x = layers.Dropout(dropout, name=f"dec_drop_{i}")(x)

        # ─── Output ───
        outputs = layers.Dense(n_features, activation="linear", name="output")(x)

        model = keras.Model(inputs=inputs, outputs=outputs, name="autoencoder")
        return model

    # ═══════════════════════════════════════════════════════
    #  Training (with Calibration Split)
    # ═══════════════════════════════════════════════════════

    @classmethod
    def train(
        cls,
        X: np.ndarray,
        *,
        hidden_dims: Optional[List[int]] = None,
        bottleneck_dim: Optional[int] = None,
        dropout: float = DEFAULT_DROPOUT,
        epochs: int = DEFAULT_EPOCHS,
        batch_size: int = DEFAULT_BATCH_SIZE,
        learning_rate: float = DEFAULT_LEARNING_RATE,
        validation_split: float = DEFAULT_VALIDATION_SPLIT,
        patience: int = DEFAULT_PATIENCE,
        threshold_percentile: float = DEFAULT_PERCENTILE,
        scale_features: bool = True,
        calibration_ratio: float = DEFAULT_CALIBRATION_RATIO,
        use_calibration: bool = True,
        random_seed: int = 42,
        verbose: int = 0,
    ) -> Dict[str, Any]:
        """
        بيدرب الـ autoencoder على بيانات "طبيعية".

        Args:
            X: numpy array (n_samples, n_features)
            hidden_dims: أبعاد الطبقات المخفية
            bottleneck_dim: بعد الـ bottleneck
            dropout: dropout rate
            epochs: عدد الـ epochs
            batch_size: batch size
            learning_rate: learning rate
            validation_split: نسبة التحقق
            patience: patience للـ early stopping
            threshold_percentile: percentile للـ threshold
            scale_features: يعمل StandardScaler؟
            calibration_ratio: نسبة البيانات للـ calibration
            use_calibration: يستخدم calibration split؟
            random_seed: بذرة الـ split
            verbose: TF verbosity

        Returns:
            dict فيه training stats
        """
        _require_tf()
        try:
            X = np.asarray(X, dtype=np.float32)

            if X.ndim == 1:
                X = X.reshape(-1, 1)

            if X.shape[0] < cls.MIN_SAMPLES:
                return {
                    "success": False,
                    "error": "insufficient_samples",
                    "min_required": cls.MIN_SAMPLES,
                    "got": int(X.shape[0]),
                }

            # عالج NaN/Inf
            X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

            n_samples, n_features = X.shape

            # default dims
            if hidden_dims is None:
                hidden_dims = [
                    max(n_features * 2, 32),
                    max(n_features, 16),
                ]

            if bottleneck_dim is None:
                bottleneck_dim = max(n_features // 2, 4)

            start_time = time.time()

            # ─── Calibration Split ───
            if use_calibration and n_samples >= cls.MIN_SAMPLES_FOR_CALIBRATION:
                n_cal = max(int(n_samples * calibration_ratio), 30)
                n_train = n_samples - n_cal

                rng = np.random.RandomState(random_seed)
                idx = rng.permutation(n_samples)

                X_train = X[idx[:n_train]]
                X_cal = X[idx[n_train:]]
                used_calibration = True
            else:
                X_train = X
                X_cal = X
                n_cal = 0
                n_train = n_samples
                used_calibration = False

            # ─── Scaling ───
            scaler = None
            X_train_s = X_train
            X_cal_s = X_cal

            if scale_features:
                scaler = StandardScaler()
                X_train_s = scaler.fit_transform(X_train).astype(np.float32)
                X_cal_s = scaler.transform(X_cal).astype(np.float32)

            # ─── Build Model ───
            model = cls._build_autoencoder(
                n_features,
                hidden_dims=hidden_dims,
                bottleneck_dim=bottleneck_dim,
                dropout=dropout,
            )

            model.compile(
                optimizer=keras.optimizers.Adam(learning_rate=learning_rate),
                loss="mse",
                metrics=["mae"],
            )

            # ─── Callbacks ───
            callbacks = [
                keras.callbacks.EarlyStopping(
                    monitor="val_loss",
                    patience=patience,
                    restore_best_weights=True,
                    verbose=0,
                ),
                keras.callbacks.ReduceLROnPlateau(
                    monitor="val_loss",
                    factor=0.5,
                    patience=3,
                    min_lr=1e-6,
                    verbose=0,
                ),
            ]

            # ─── Train (على training subset بس) ───
            history = model.fit(
                X_train_s,
                X_train_s,
                epochs=epochs,
                batch_size=batch_size,
                validation_split=validation_split,
                callbacks=callbacks,
                shuffle=True,
                verbose=verbose,
            )

            # ─── Compute threshold من calibration set ───
            if used_calibration:
                cal_pred = model.predict(X_cal_s, verbose=0)
                cal_errors = np.mean(
                    (X_cal_s - cal_pred) ** 2, axis=1
                )
                threshold = float(
                    np.percentile(cal_errors, threshold_percentile)
                )
            else:
                train_pred = model.predict(X_train_s, verbose=0)
                cal_errors = np.mean(
                    (X_train_s - train_pred) ** 2, axis=1
                )
                threshold = float(
                    np.percentile(cal_errors, threshold_percentile)
                )

            # ─── Stats على كل البيانات ───
            if scale_features:
                X_full_s = scaler.transform(X).astype(np.float32)
            else:
                X_full_s = X.astype(np.float32)

            full_pred = model.predict(X_full_s, verbose=0)
            reconstruction_errors = np.mean(
                (X_full_s - full_pred) ** 2, axis=1
            )

            n_anomaly_train = int(np.sum(reconstruction_errors > threshold))
            anomaly_ratio = n_anomaly_train / n_samples

            training_time = time.time() - start_time
            final_epochs = len(history.history.get("loss", []))

            # ─── Save as singleton ───
            cls._model = model
            cls._scaler = scaler
            cls._is_trained = True
            cls._threshold = threshold
            cls._n_features = n_features
            cls._training_stats = {
                "n_samples": int(n_samples),
                "n_features": int(n_features),
                "hidden_dims": list(hidden_dims),
                "bottleneck_dim": int(bottleneck_dim),
                "dropout": float(dropout),
                "epochs_requested": int(epochs),
                "epochs_completed": int(final_epochs),
                "batch_size": int(batch_size),
                "learning_rate": float(learning_rate),
                "threshold_percentile": float(threshold_percentile),
                "threshold": float(threshold),
                "used_calibration": bool(used_calibration),
                "n_train": int(n_train),
                "n_calibration": int(n_cal),
                "calibration_errors_mean": float(np.mean(cal_errors)),
                "calibration_errors_std": float(np.std(cal_errors)),
                "final_loss": float(history.history["loss"][-1]),
                "final_val_loss": float(
                    history.history.get("val_loss", [0.0])[-1]
                ),
                "best_val_loss": float(
                    min(history.history.get("val_loss", [0.0]))
                ),
                "reconstruction_err_mean": float(np.mean(reconstruction_errors)),
                "reconstruction_err_std": float(np.std(reconstruction_errors)),
                "reconstruction_err_max": float(np.max(reconstruction_errors)),
                "n_anomaly_train": n_anomaly_train,
                "anomaly_ratio": float(anomaly_ratio),
                "training_time_sec": round(training_time, 3),
                "trained_at": time.time(),
            }

            logger.info(
                "autoencoder_trained",
                n_samples=n_samples,
                n_train=n_train,
                n_cal=n_cal,
                n_features=n_features,
                epochs=final_epochs,
                final_loss=round(cls._training_stats["final_loss"], 4),
                threshold=round(threshold, 4),
                used_calibration=used_calibration,
                training_time_sec=round(training_time, 3),
            )

            return {
                "success": True,
                **cls._training_stats,
            }

        except Exception as e:
            logger.error("autoencoder_train_failed", error=str(e))
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
        """بيتنبأ بـ normal/anomaly باستخدام reconstruction error."""
        if not cls.is_trained():
            return {
                "success": False,
                "error": "model_not_trained",
                "is_anomaly": False,
                "anomaly_score": 0.0,
            }

        try:
            X = np.asarray(X, dtype=np.float32)

            # ─── Single sample detection ───
            if X.ndim == 1:
                X = X.reshape(1, -1)
                single = True
            elif X.ndim == 2 and X.shape[0] == 1:
                single = True
            else:
                single = False

            X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

            # scale
            if cls._scaler is not None:
                X = cls._scaler.transform(X).astype(np.float32)

            # predict (reconstruct)
            X_pred = cls._model.predict(X, verbose=0)

            # reconstruction error per sample
            errors = np.mean((X - X_pred) ** 2, axis=1)

            predictions = np.where(errors > cls._threshold, -1, 1)

            if single:
                return {
                    "success": True,
                    "is_anomaly": bool(predictions[0] == -1),
                    "anomaly_score": float(errors[0]),
                    "reconstruction_error": float(errors[0]),
                    "threshold": float(cls._threshold),
                    "prediction": int(predictions[0]),
                }

            return {
                "success": True,
                "predictions": [int(p) for p in predictions],
                "anomaly_scores": [float(e) for e in errors],
                "reconstruction_errors": [float(e) for e in errors],
                "threshold": float(cls._threshold),
                "n_anomalies": int(np.sum(predictions == -1)),
                "n_normal": int(np.sum(predictions == 1)),
            }

        except Exception as e:
            logger.error("autoencoder_predict_failed", error=str(e))
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
            X = np.asarray(X, dtype=np.float32)
            if X.ndim == 1:
                X = X.reshape(1, -1)

            X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

            if cls._scaler is not None:
                X = cls._scaler.transform(X).astype(np.float32)

            X_pred = cls._model.predict(X, verbose=0)
            errors = np.mean((X - X_pred) ** 2, axis=1)
            predictions = np.where(errors > cls._threshold, -1, 1)

            results = []
            for i in range(len(predictions)):
                is_anom = bool(predictions[i] == -1)
                if return_only_anomalies and not is_anom:
                    continue

                results.append({
                    "index": i,
                    "is_anomaly": is_anom,
                    "anomaly_score": float(errors[i]),
                    "reconstruction_error": float(errors[i]),
                })

            return results

        except Exception as e:
            logger.error("autoencoder_batch_predict_failed", error=str(e))
            return []

    # ═══════════════════════════════════════════════════════
    #  Anomaly Detection Helpers
    # ═══════════════════════════════════════════════════════

    @classmethod
    def is_anomaly(
        cls,
        X: np.ndarray,
        threshold: Optional[float] = None,
    ) -> bool:
        """بيتحقق لو sample واحدة anomaly."""
        result = cls.predict(X)

        if not result.get("success"):
            return False

        if threshold is not None:
            return result.get("anomaly_score", 0.0) > threshold

        return result.get("is_anomaly", False)

    @classmethod
    def get_anomaly_score(cls, X: np.ndarray) -> float:
        """بيرجع anomaly score (reconstruction error)."""
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
            model_path = cls._model_path(name)
            meta_path = cls._meta_path(name)

            cls._model.save(model_path)

            payload = {
                "scaler": cls._scaler,
                "threshold": cls._threshold,
                "n_features": cls._n_features,
                "training_stats": cls._training_stats,
                "metadata": cls._metadata,
                "saved_at": time.time(),
                "version": "1.1",
            }
            joblib.dump(payload, meta_path)

            logger.info(
                "autoencoder_saved",
                model_path=model_path,
                meta_path=meta_path,
            )

            total_size = (
                os.path.getsize(model_path)
                if os.path.isfile(model_path)
                else sum(
                    os.path.getsize(os.path.join(dp, f))
                    for dp, _, fs in os.walk(model_path)
                    for f in fs
                )
            )

            return {
                "success": True,
                "model_path": model_path,
                "meta_path": meta_path,
                "size_bytes": total_size,
            }

        except Exception as e:
            logger.error("autoencoder_save_failed", error=str(e))
            return {"success": False, "error": str(e)}

    @classmethod
    def load(cls, name: Optional[str] = None) -> Dict[str, Any]:
        """بيحمّل الموديل من disk."""
        _require_tf()
        try:
            model_path = cls._model_path(name)
            meta_path = cls._meta_path(name)

            if not os.path.exists(model_path):
                return {
                    "success": False,
                    "error": "model_file_not_found",
                    "path": model_path,
                }

            if not os.path.exists(meta_path):
                return {
                    "success": False,
                    "error": "meta_file_not_found",
                    "path": meta_path,
                }

            cls._model = keras.models.load_model(model_path)

            payload = joblib.load(meta_path)
            cls._scaler = payload.get("scaler")
            cls._threshold = payload.get("threshold", 0.0)
            cls._n_features = payload.get("n_features", 0)
            cls._training_stats = payload.get("training_stats", {})
            cls._metadata = payload.get("metadata", {})
            cls._is_trained = cls._model is not None

            logger.info("autoencoder_loaded", path=model_path)

            return {
                "success": True,
                "model_path": model_path,
                "meta_path": meta_path,
                "trained_at": cls._training_stats.get("trained_at"),
                "threshold": cls._threshold,
            }

        except Exception as e:
            logger.error("autoencoder_load_failed", error=str(e))
            return {"success": False, "error": str(e)}

    @classmethod
    def delete_model(cls, name: Optional[str] = None) -> bool:
        """بيمسح ملفات الموديل."""
        try:
            import shutil

            model_path = cls._model_path(name)
            meta_path = cls._meta_path(name)

            deleted = False

            if os.path.exists(model_path):
                if os.path.isdir(model_path):
                    shutil.rmtree(model_path)
                else:
                    os.remove(model_path)
                deleted = True

            if os.path.exists(meta_path):
                os.remove(meta_path)
                deleted = True

            return deleted

        except Exception as e:
            logger.error("autoencoder_delete_failed", error=str(e))
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
            "n_features": cls._n_features,
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

    @classmethod
    def get_model_summary(cls) -> Optional[str]:
        """بيرجع ملخص الموديل."""
        if not cls.is_trained():
            return None

        try:
            lines = []
            cls._model.summary(print_fn=lines.append)
            return "\n".join(lines)
        except Exception:
            return None

    # ═══════════════════════════════════════════════════════
    #  Reset
    # ═══════════════════════════════════════════════════════

    @classmethod
    def reset(cls) -> None:
        """بيمسح الموديل من الـ memory."""
        _require_tf()
        cls._model = None
        cls._scaler = None
        cls._is_trained = False
        cls._training_stats = {}
        cls._metadata = {}
        cls._threshold = 0.0
        cls._n_features = 0

        try:
            keras.backend.clear_session()
        except Exception:
            pass

        logger.info("autoencoder_reset")


# ─── Standalone functions ─────────────────────────────

def train_detector(
    X: np.ndarray,
    **kwargs,
) -> Dict[str, Any]:
    """Shortcut for AutoencoderDetector.train."""
    return AutoencoderDetector.train(X, **kwargs)


def predict_anomaly(X: np.ndarray) -> Dict[str, Any]:
    """Shortcut for AutoencoderDetector.predict."""
    return AutoencoderDetector.predict(X)


def is_anomaly(X: np.ndarray) -> bool:
    """Shortcut for AutoencoderDetector.is_anomaly."""
    return AutoencoderDetector.is_anomaly(X)


def get_reconstruction_error(X: np.ndarray) -> float:
    """Shortcut for AutoencoderDetector.get_anomaly_score."""
    return AutoencoderDetector.get_anomaly_score(X)

# ─── Standalone functions ─────────────────────────────

def train_detector(
    X: np.ndarray,
    **kwargs,
) -> Dict[str, Any]:
    """Shortcut for AutoencoderDetector.train."""
    return AutoencoderDetector.train(X, **kwargs)


def predict_anomaly(X: np.ndarray) -> Dict[str, Any]:
    """Shortcut for AutoencoderDetector.predict."""
    return AutoencoderDetector.predict(X)


def is_anomaly(X: np.ndarray) -> bool:
    """Shortcut for AutoencoderDetector.is_anomaly."""
    return AutoencoderDetector.is_anomaly(X)


def get_reconstruction_error(X: np.ndarray) -> float:
    """Shortcut for AutoencoderDetector.get_anomaly_score."""
    return AutoencoderDetector.get_anomaly_score(X)