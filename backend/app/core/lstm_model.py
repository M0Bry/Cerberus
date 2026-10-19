"""
LSTM Model — LSTM Autoencoder for temporal anomaly detection.

بيوفر:
- LSTM Autoencoder (sequence-to-sequence)
- Training on normal sequences
- Anomaly score = sequence reconstruction error
- Calibration split for accurate threshold
- Sliding window support (للـ single samples)
- Model persistence (save/load)
- Batch prediction
- Model statistics

الفكرة:
- LSTM Autoencoder بيتدرب على "تسلسلات طبيعية"
- بيتعلم يعيد بناء التسلسل
- لو تسلسل جديد شاذ → reconstruction error عالي
- مناسب لـ:
  * Session-based analysis
  * User behavior over time
  * Request sequences
  * Login patterns

الاستخدام:
- session_analyzer.py
- user_baseline.py
- attack_chain.py
- anomaly_detection.py
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

# TensorFlow imports
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


class LSTMModel:
    """
    LSTM Autoencoder Anomaly Detector.

    الفكرة:
    - Input: (batch, seq_len, n_features)
    - Encoder: LSTM بيتحول التسلسل لـ vector (latent)
    - Decoder: LSTM بيعيد بناء التسلسل
    - anomaly_score = reconstruction error
    """

    # ─── Config ────────────────────────────────────────────
    MODEL_DIR = "storage/models"
    MODEL_NAME = "lstm_model.keras"
    META_NAME = "lstm_model_meta.pkl"

    # ─── Architecture ─────────────────────────────────────
    DEFAULT_HIDDEN_DIM = 32
    DEFAULT_LATENT_DIM = 16
    DEFAULT_DROPOUT = 0.2

    # ─── Training ─────────────────────────────────────────
    DEFAULT_EPOCHS = 50
    DEFAULT_BATCH_SIZE = 32
    DEFAULT_LEARNING_RATE = 1e-3
    DEFAULT_VALIDATION_SPLIT = 0.1
    DEFAULT_PATIENCE = 5
    MIN_SAMPLES = 50

    # ─── Sequence ─────────────────────────────────────────
    DEFAULT_SEQ_LENGTH = 10

    # ─── Calibration ──────────────────────────────────────
    DEFAULT_CALIBRATION_RATIO = 0.2
    MIN_SAMPLES_FOR_CALIBRATION = 200

    # ─── Threshold ────────────────────────────────────────
    DEFAULT_PERCENTILE = 97.0
    DEFAULT_ANOMALY_THRESHOLD = 0.0

    # ─── State ────────────────────────────────────────────
    _model: Optional[keras.Model] = None
    _scaler: Optional[StandardScaler] = None
    _is_trained: bool = False
    _training_stats: Dict[str, Any] = {}
    _metadata: Dict[str, Any] = {}
    _threshold: float = 0.0
    _seq_length: int = 0
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

    @classmethod
    def get_seq_length(cls) -> int:
        """بيرجع طول التسلسل."""
        return cls._seq_length

    # ═══════════════════════════════════════════════════════
    #  Build Model
    # ═══════════════════════════════════════════════════════

    @classmethod
    def _build_lstm_autoencoder(
        cls,
        seq_length: int,
        n_features: int,
        *,
        hidden_dim: int,
        latent_dim: int,
        dropout: float,
    ) -> keras.Model:
        """
        بيبني LSTM autoencoder.

        Input:  (batch, seq_length, n_features)
        Output: (batch, seq_length, n_features)
        """
        _require_tf()
        # ─── Encoder ───
        inputs = keras.Input(
            shape=(seq_length, n_features),
            name="input",
        )

        # Encoder LSTM
        x = layers.LSTM(
            hidden_dim,
            activation="tanh",
            return_sequences=True,
            name="enc_lstm_1",
        )(inputs)
        if dropout > 0:
            x = layers.Dropout(dropout, name="enc_drop_1")(x)

        # ─── Bottleneck (latent) ───
        latent = layers.LSTM(
            latent_dim,
            activation="tanh",
            return_sequences=False,
            name="bottleneck",
        )(x)
        if dropout > 0:
            latent = layers.Dropout(dropout, name="bottleneck_drop")(latent)

        # ─── RepeatVector: (batch, latent) → (batch, seq_length, latent) ───
        x = layers.RepeatVector(seq_length, name="repeat")(latent)

        # ─── Decoder ───
        x = layers.LSTM(
            latent_dim,
            activation="tanh",
            return_sequences=True,
            name="dec_lstm_1",
        )(x)
        if dropout > 0:
            x = layers.Dropout(dropout, name="dec_drop_1")(x)

        x = layers.LSTM(
            hidden_dim,
            activation="tanh",
            return_sequences=True,
            name="dec_lstm_2",
        )(x)
        if dropout > 0:
            x = layers.Dropout(dropout, name="dec_drop_2")(x)

        # ─── Output: TimeDistributed Dense ───
        outputs = layers.TimeDistributed(
            layers.Dense(n_features, activation="linear"),
            name="output",
        )(x)

        model = keras.Model(
            inputs=inputs,
            outputs=outputs,
            name="lstm_autoencoder",
        )
        return model

    # ═══════════════════════════════════════════════════════
    #  Sequence Preparation
    # ═══════════════════════════════════════════════════════

    @classmethod
    def _prepare_sequences(
        cls,
        X: np.ndarray,
        seq_length: int,
    ) -> np.ndarray:
        """
        بيعمل sliding windows من البيانات.

        Input:  (n_samples, n_features)
        Output: (n_sequences, seq_length, n_features)
        """
        X = np.asarray(X, dtype=np.float32)
        if X.ndim != 2:
            raise ValueError(f"Expected 2D array, got {X.ndim}D")

        n_samples, n_features = X.shape
        if n_samples < seq_length:
            return np.array([])

        n_sequences = n_samples - seq_length + 1

        sequences = np.zeros(
            (n_sequences, seq_length, n_features),
            dtype=np.float32,
        )

        for i in range(n_sequences):
            sequences[i] = X[i:i + seq_length]

        return sequences

    # ═══════════════════════════════════════════════════════
    #  Training
    # ═══════════════════════════════════════════════════════

    @classmethod
    def train(
        cls,
        X: np.ndarray,
        *,
        seq_length: int = DEFAULT_SEQ_LENGTH,
        hidden_dim: int = DEFAULT_HIDDEN_DIM,
        latent_dim: int = DEFAULT_LATENT_DIM,
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
        بيدرب LSTM autoencoder على تسلسلات "طبيعية".

        Args:
            X: numpy array (n_samples, n_features)
               سيتم تحويله لـ sequences عبر sliding window
            seq_length: طول التسلسل
            hidden_dim: LSTM hidden units
            latent_dim: بعد الـ bottleneck
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

            n_samples, n_features = X.shape

            if n_samples < seq_length + 10:
                return {
                    "success": False,
                    "error": "insufficient_samples",
                    "min_required": seq_length + 10,
                    "got": int(n_samples),
                }

            # عالج NaN/Inf
            X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

            start_time = time.time()

            # ─── Scaling (قبل الـ sequence prep) ───
            scaler = None
            X_scaled = X
            if scale_features:
                scaler = StandardScaler()
                X_scaled = scaler.fit_transform(X).astype(np.float32)

            # ─── Prepare Sequences ───
            sequences = cls._prepare_sequences(X_scaled, seq_length)
            n_sequences = len(sequences)

            if n_sequences < cls.MIN_SAMPLES:
                return {
                    "success": False,
                    "error": "insufficient_sequences",
                    "min_required": cls.MIN_SAMPLES,
                    "got": int(n_sequences),
                }

            # ─── Calibration Split (على sequences) ───
            if use_calibration and n_sequences >= cls.MIN_SAMPLES_FOR_CALIBRATION:
                n_cal = max(int(n_sequences * calibration_ratio), 30)
                n_train = n_sequences - n_cal

                rng = np.random.RandomState(random_seed)
                idx = rng.permutation(n_sequences)

                X_train = sequences[idx[:n_train]]
                X_cal = sequences[idx[n_train:]]
                used_calibration = True
            else:
                X_train = sequences
                X_cal = sequences
                n_cal = 0
                n_train = n_sequences
                used_calibration = False

            # ─── Build Model ───
            model = cls._build_lstm_autoencoder(
                seq_length,
                n_features,
                hidden_dim=hidden_dim,
                latent_dim=latent_dim,
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

            # ─── Train ───
            history = model.fit(
                X_train,
                X_train,
                epochs=epochs,
                batch_size=batch_size,
                validation_split=validation_split,
                callbacks=callbacks,
                shuffle=True,
                verbose=verbose,
            )

            # ─── Compute threshold ───
            if used_calibration:
                cal_pred = model.predict(X_cal, verbose=0)
                cal_errors = np.mean(
                    (X_cal - cal_pred) ** 2, axis=(1, 2)
                )
                threshold = float(
                    np.percentile(cal_errors, threshold_percentile)
                )
            else:
                train_pred = model.predict(X_train, verbose=0)
                cal_errors = np.mean(
                    (X_train - train_pred) ** 2, axis=(1, 2)
                )
                threshold = float(
                    np.percentile(cal_errors, threshold_percentile)
                )

            # ─── Stats ───
            full_pred = model.predict(sequences, verbose=0)
            reconstruction_errors = np.mean(
                (sequences - full_pred) ** 2, axis=(1, 2)
            )

            n_anomaly_train = int(np.sum(reconstruction_errors > threshold))
            anomaly_ratio = n_anomaly_train / n_sequences

            training_time = time.time() - start_time
            final_epochs = len(history.history.get("loss", []))

            # ─── Save as singleton ───
            cls._model = model
            cls._scaler = scaler
            cls._is_trained = True
            cls._threshold = threshold
            cls._seq_length = seq_length
            cls._n_features = n_features
            cls._training_stats = {
                "n_samples": int(n_samples),
                "n_features": int(n_features),
                "n_sequences": int(n_sequences),
                "seq_length": int(seq_length),
                "hidden_dim": int(hidden_dim),
                "latent_dim": int(latent_dim),
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
                "lstm_trained",
                n_samples=n_samples,
                n_sequences=n_sequences,
                seq_length=seq_length,
                n_features=n_features,
                n_train=n_train,
                n_cal=n_cal,
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
            logger.error("lstm_train_failed", error=str(e))
            return {
                "success": False,
                "error": str(e),
            }

    # ═══════════════════════════════════════════════════════
    #  Prediction
    # ═══════════════════════════════════════════════════════

    @classmethod
    def _prepare_input(
        cls,
        X: np.ndarray,
        single: bool = False,
    ) -> Tuple[np.ndarray, bool]:
        """
        بيجهز الـ input للـ model.

        يقبل:
        - (n_samples, n_features) → يحولها لـ sequences
        - (n_samples, seq_length, n_features) → جاهزة
        - (seq_length, n_features) → single sequence
        - (n_features,) → sample واحد
        """
        X = np.asarray(X, dtype=np.float32)
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

        seq_length = cls._seq_length
        n_features = cls._n_features

        # Case 1: 1D — sample واحد
        if X.ndim == 1:
            if seq_length == 1:
                return X.reshape(1, 1, -1), True
            tiled = np.tile(X, (seq_length, 1))
            return tiled.reshape(1, seq_length, -1), True

        # Case 2: 2D
        if X.ndim == 2:
            n_rows, n_cols = X.shape

            # (seq_length, n_features) → single sequence
            if n_rows == seq_length and n_cols == n_features:
                return X.reshape(1, seq_length, n_features), True

            # (n_samples, n_features) → sequences عبر sliding window
            if n_cols == n_features:
                sequences = cls._prepare_sequences(X, seq_length)
                if len(sequences) == 0:
                    tiled = np.tile(X[-1], (seq_length, 1))
                    return tiled.reshape(1, seq_length, n_features), True
                return sequences, False

            return np.array([]), False

        # Case 3: 3D
        if X.ndim == 3:
            n_seqs, sl, nf = X.shape
            if sl != seq_length or nf != n_features:
                return np.array([]), False
            return X, n_seqs == 1

        return np.array([]), False

    @classmethod
    def _apply_scaling(cls, X: np.ndarray) -> np.ndarray:
        """
        بيعمل scaling للـ input حسب شكله (1D/2D/3D).

        ملاحظة مهمة: Model اتدرب على data scaled،
        فلازم نعمل scale للـ input في كل الحالات.
        """
        if cls._scaler is None:
            return X

        n_features = cls._n_features
        if n_features == 0:
            return X

        try:
            # Case 1: 1D
            if X.ndim == 1:
                if X.shape[0] != n_features:
                    return X
                scaled = cls._scaler.transform(
                    X.reshape(1, -1)
                ).astype(np.float32)
                return scaled.reshape(-1)

            # Case 2: 2D — columns == n_features
            if X.ndim == 2 and X.shape[1] == n_features:
                return cls._scaler.transform(X).astype(np.float32)

            # Case 3: 3D — (n_seqs, seq_len, n_features)
            if X.ndim == 3 and X.shape[2] == n_features:
                n_seqs, sl, nf = X.shape
                flat = X.reshape(-1, nf)
                flat_scaled = cls._scaler.transform(flat).astype(np.float32)
                return flat_scaled.reshape(n_seqs, sl, nf)

            return X

        except Exception as e:
            logger.warning("lstm_scaling_failed", error=str(e))
            return X

    @classmethod
    def predict(
        cls,
        X: np.ndarray,
    ) -> Dict[str, Any]:
        """
        بيتنبأ بـ normal/anomaly.

        Args:
            X: 
                - (n_samples, n_features) → sequences تلقائياً
                - (n_samples, seq_length, n_features) → sequences جاهزة
                - (seq_length, n_features) → single sequence
                - (n_features,) → single sample (يُكرر)

        Returns:
            dict فيه: is_anomaly, anomaly_score, reconstruction_error
        """
        if not cls.is_trained():
            return {
                "success": False,
                "error": "model_not_trained",
                "is_anomaly": False,
                "anomaly_score": 0.0,
            }

        try:
            X_in = np.asarray(X, dtype=np.float32)
            X_in = np.nan_to_num(X_in, nan=0.0, posinf=0.0, neginf=0.0)

            # ─── Scaling: يعمل للـ 1D / 2D / 3D ───
            X_in = cls._apply_scaling(X_in)

            sequences, single = cls._prepare_input(X_in, single=False)

            if len(sequences) == 0:
                return {
                    "success": False,
                    "error": "invalid_input_shape",
                    "is_anomaly": False,
                    "anomaly_score": 0.0,
                }

            # Predict
            X_pred = cls._model.predict(sequences, verbose=0)
            errors = np.mean((sequences - X_pred) ** 2, axis=(1, 2))

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
            logger.error("lstm_predict_failed", error=str(e))
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
        """بيتنبأ لمجموعة sequences."""
        if not cls.is_trained():
            return []

        try:
            result = cls.predict(X)

            if not result.get("success"):
                return []

            # لو single → لفة واحدة
            if "is_anomaly" in result and "predictions" not in result:
                if return_only_anomalies and not result["is_anomaly"]:
                    return []
                return [{
                    "index": 0,
                    "is_anomaly": result["is_anomaly"],
                    "anomaly_score": result["anomaly_score"],
                }]

            predictions = result["predictions"]
            anomaly_scores = result["anomaly_scores"]

            results = []
            for i in range(len(predictions)):
                is_anom = predictions[i] == -1
                if return_only_anomalies and not is_anom:
                    continue

                results.append({
                    "index": i,
                    "is_anomaly": is_anom,
                    "anomaly_score": anomaly_scores[i],
                })

            return results

        except Exception as e:
            logger.error("lstm_batch_predict_failed", error=str(e))
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
        """بيتحقق لو sequence واحدة anomaly."""
        result = cls.predict(X)

        if not result.get("success"):
            return False

        if threshold is not None:
            if "is_anomaly" in result and "predictions" not in result:
                return result.get("anomaly_score", 0.0) > threshold
            return any(
                s > threshold
                for s in result.get("anomaly_scores", [])
            )

        if "is_anomaly" in result and "predictions" not in result:
            return result.get("is_anomaly", False)

        return result.get("n_anomalies", 0) > 0

    @classmethod
    def get_anomaly_score(cls, X: np.ndarray) -> float:
        """بيرجع anomaly score (أعلى score)."""
        result = cls.predict(X)
        if not result.get("success"):
            return 0.0

        if "is_anomaly" in result and "predictions" not in result:
            return result.get("anomaly_score", 0.0)

        scores = result.get("anomaly_scores", [])
        return float(max(scores)) if scores else 0.0

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
                "seq_length": cls._seq_length,
                "n_features": cls._n_features,
                "training_stats": cls._training_stats,
                "metadata": cls._metadata,
                "saved_at": time.time(),
                "version": "1.1",
            }
            joblib.dump(payload, meta_path)

            logger.info(
                "lstm_saved",
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
            logger.error("lstm_save_failed", error=str(e))
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
            cls._seq_length = payload.get("seq_length", 0)
            cls._n_features = payload.get("n_features", 0)
            cls._training_stats = payload.get("training_stats", {})
            cls._metadata = payload.get("metadata", {})
            cls._is_trained = cls._model is not None

            logger.info("lstm_loaded", path=model_path)

            return {
                "success": True,
                "model_path": model_path,
                "meta_path": meta_path,
                "trained_at": cls._training_stats.get("trained_at"),
                "threshold": cls._threshold,
                "seq_length": cls._seq_length,
            }

        except Exception as e:
            logger.error("lstm_load_failed", error=str(e))
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
            logger.error("lstm_delete_failed", error=str(e))
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
            "seq_length": cls._seq_length,
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
        cls._seq_length = 0
        cls._n_features = 0

        try:
            keras.backend.clear_session()
        except Exception:
            pass

        logger.info("lstm_reset")


# ─── Standalone functions ─────────────────────────────

def train_detector(
    X: np.ndarray,
    **kwargs,
) -> Dict[str, Any]:
    """Shortcut for LSTMModel.train."""
    return LSTMModel.train(X, **kwargs)


def predict_anomaly(X: np.ndarray) -> Dict[str, Any]:
    """Shortcut for LSTMModel.predict."""
    return LSTMModel.predict(X)


def is_anomaly(X: np.ndarray) -> bool:
    """Shortcut for LSTMModel.is_anomaly."""
    return LSTMModel.is_anomaly(X)


def get_reconstruction_error(X: np.ndarray) -> float:
    """Shortcut for LSTMModel.get_anomaly_score."""
    return LSTMModel.get_anomaly_score(X)