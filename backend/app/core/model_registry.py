"""
Model Registry — Central registry for all ML models.

بيوفر:
- Central registry لكل الـ ML models
- Register / Unregister models
- Load / Save all models
- List models + status
- Active model management
- Model versioning + metadata
- Health check (is_trained + file existence)
- Delete models
- Reset all models
- Registry persistence (JSON)

الفكرة:
- Single source of truth لكل الموديلات
- يسهّل إدارة الـ 8 models من مكان واحد
- مناسب لـ:
  * Server startup (load_all)
  * Health checks
  * Model switching without restart
  * Rollback

الاستخدام:
- main.py / lifespan.py
- defense_service.py
- admin endpoints
- monitoring
"""

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Type

import structlog

logger = structlog.get_logger()


class ModelRegistry:
    """
    Central Model Registry.

    الفكرة:
    - كل موديل بيسجل نفسه مع اسمه + الـ class بتاعه
    - الـ registry بيدير كل الموديلات من مكان واحد
    - بيحفظ metadata في JSON file
    """

    # ─── Config ────────────────────────────────────────────
    MODEL_DIR = "storage/models"
    REGISTRY_FILE = "registry.json"

    # ─── Registry State ───────────────────────────────────
    _models: Dict[str, Dict[str, Any]] = {}
    _active_model: Optional[str] = None
    _is_loaded: bool = False

    # ═══════════════════════════════════════════════════════
    #  Internal Helpers
    # ═══════════════════════════════════════════════════════

    @classmethod
    def _ensure_dir(cls) -> None:
        """بيتأكد إن مجلد الموديلات موجود."""
        Path(cls.MODEL_DIR).mkdir(parents=True, exist_ok=True)

    @classmethod
    def _registry_path(cls) -> str:
        """بيرجع مسار ملف الـ registry."""
        return os.path.join(cls.MODEL_DIR, cls.REGISTRY_FILE)

    @classmethod
    def _save_registry(cls) -> bool:
        """بيحفظ الـ registry metadata على disk."""
        try:
            cls._ensure_dir()

            payload = {
                "models": {
                    name: {
                        "class_name": info.get("class_name"),
                        "module": info.get("module"),
                        "description": info.get("description", ""),
                        "version": info.get("version", "1.0"),
                        "tags": info.get("tags", []),
                        "registered_at": info.get("registered_at"),
                        "last_saved_at": info.get("last_saved_at"),
                        "last_loaded_at": info.get("last_loaded_at"),
                    }
                    for name, info in cls._models.items()
                },
                "active_model": cls._active_model,
                "saved_at": time.time(),
                "version": "1.0",
            }

            with open(cls._registry_path(), "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)

            return True

        except Exception as e:
            logger.error("registry_save_failed", error=str(e))
            return False

    @classmethod
    def _load_registry(cls) -> bool:
        """بيحمّل الـ registry metadata من disk."""
        try:
            path = cls._registry_path()
            if not os.path.exists(path):
                return False

            with open(path, "r", encoding="utf-8") as f:
                payload = json.load(f)

            # استرجع metadata للـ models الموجودة
            for name, info in payload.get("models", {}).items():
                if name in cls._models:
                    cls._models[name].update({
                        "description": info.get("description", ""),
                        "version": info.get("version", "1.0"),
                        "tags": info.get("tags", []),
                        "registered_at": info.get("registered_at"),
                        "last_saved_at": info.get("last_saved_at"),
                        "last_loaded_at": info.get("last_loaded_at"),
                    })

            cls._active_model = payload.get("active_model")
            cls._is_loaded = True

            return True

        except Exception as e:
            logger.error("registry_load_failed", error=str(e))
            return False

    # ═══════════════════════════════════════════════════════
    #  Registration
    # ═══════════════════════════════════════════════════════

    @classmethod
    def register(
        cls,
        name: str,
        model_class: Type,
        *,
        description: str = "",
        version: str = "1.0",
        tags: Optional[List[str]] = None,
        overwrite: bool = False,
    ) -> Dict[str, Any]:
        """
        بيسجل موديل جديد.

        Args:
            name: اسم الموديل (مثلاً: "svm", "lof")
            model_class: الـ class بتاع الموديل
            description: وصف مختصر
            version: إصدار الموديل
            tags: tags للتصنيف
            overwrite: يستبدل لو موجود؟

        Returns:
            dict فيه success + info
        """
        try:
            if not name or not model_class:
                return {
                    "success": False,
                    "error": "missing_name_or_class",
                }

            # تحقق إن الـ class فيه الدوال المطلوبة
            required_methods = ["is_trained", "train", "predict"]
            missing = [
                m for m in required_methods
                if not hasattr(model_class, m)
            ]

            if missing:
                return {
                    "success": False,
                    "error": "missing_required_methods",
                    "missing": missing,
                }

            if name in cls._models and not overwrite:
                return {
                    "success": False,
                    "error": "already_registered",
                    "name": name,
                }

            cls._models[name] = {
                "class": model_class,
                "class_name": model_class.__name__,
                "module": model_class.__module__,
                "description": description,
                "version": version,
                "tags": tags or [],
                "registered_at": time.time(),
                "last_saved_at": None,
                "last_loaded_at": None,
            }

            logger.info(
                "model_registered",
                name=name,
                class_name=model_class.__name__,
                version=version,
            )

            cls._save_registry()

            return {
                "success": True,
                "name": name,
                "class_name": model_class.__name__,
                "version": version,
            }

        except Exception as e:
            logger.error("registry_register_failed", error=str(e), name=name)
            return {"success": False, "error": str(e)}

    @classmethod
    def unregister(cls, name: str) -> Dict[str, Any]:
        """بيشيل موديل من الـ registry (من غير ما يمسح الملفات)."""
        if name not in cls._models:
            return {
                "success": False,
                "error": "not_registered",
                "name": name,
            }

        del cls._models[name]

        if cls._active_model == name:
            cls._active_model = None

        cls._save_registry()

        logger.info("model_unregistered", name=name)

        return {"success": True, "name": name}

    @classmethod
    def is_registered(cls, name: str) -> bool:
        """بيتحقق لو الموديل مسجل."""
        return name in cls._models

    @classmethod
    def get_model_class(cls, name: str) -> Optional[Type]:
        """بيرجع الـ class بتاع الموديل."""
        info = cls._models.get(name)
        return info.get("class") if info else None

    # ═══════════════════════════════════════════════════════
    #  List & Info
    # ═══════════════════════════════════════════════════════

    @classmethod
    def list_models(cls) -> List[str]:
        """بيرجع قائمة أسماء كل الموديلات المسجلة."""
        return list(cls._models.keys())

    @classmethod
    def get_info(cls, name: str) -> Optional[Dict[str, Any]]:
        """بيرجع metadata موديل معين."""
        info = cls._models.get(name)
        if not info:
            return None

        return {
            "name": name,
            "class_name": info.get("class_name"),
            "module": info.get("module"),
            "description": info.get("description", ""),
            "version": info.get("version", "1.0"),
            "tags": info.get("tags", []),
            "is_trained": cls._is_model_trained(name),
            "is_active": name == cls._active_model,
            "registered_at": info.get("registered_at"),
            "last_saved_at": info.get("last_saved_at"),
            "last_loaded_at": info.get("last_loaded_at"),
        }

    @classmethod
    def get_all_info(cls) -> Dict[str, Any]:
        """بيرجع info كل الموديلات."""
        return {
            "total": len(cls._models),
            "active": cls._active_model,
            "models": {
                name: cls.get_info(name)
                for name in cls._models.keys()
            },
        }

    @classmethod
    def _is_model_trained(cls, name: str) -> bool:
        """بيتحقق لو الموديل متدرب (بدون رفع exceptions)."""
        info = cls._models.get(name)
        if not info:
            return False

        try:
            model_class = info.get("class")
            if not model_class:
                return False
            return bool(model_class.is_trained())
        except Exception:
            return False

    # ═══════════════════════════════════════════════════════
    #  Active Model
    # ═══════════════════════════════════════════════════════

    @classmethod
    def set_active(cls, name: str) -> Dict[str, Any]:
        """بيحدد الموديل النشط."""
        if name not in cls._models:
            return {
                "success": False,
                "error": "not_registered",
                "name": name,
            }

        cls._active_model = name
        cls._save_registry()

        logger.info("active_model_set", name=name)

        return {"success": True, "active": name}

    @classmethod
    def get_active(cls) -> Optional[str]:
        """بيرجع اسم الموديل النشط."""
        return cls._active_model

    @classmethod
    def get_active_model_class(cls) -> Optional[Type]:
        """بيرجع الـ class بتاع الموديل النشط."""
        if not cls._active_model:
            return None
        return cls.get_model_class(cls._active_model)

    # ═══════════════════════════════════════════════════════
    #  Load / Save All
    # ═══════════════════════════════════════════════════════

    @classmethod
    def load_all(
        cls,
        *,
        skip_missing: bool = True,
    ) -> Dict[str, Any]:
        """
        بيحمّل كل الموديلات من disk.

        Args:
            skip_missing: يتجاهل الموديلات اللي مفيهاش ملفات؟

        Returns:
            dict فيه: loaded, failed, skipped
        """
        loaded = []
        failed = []
        skipped = []

        for name, info in cls._models.items():
            model_class = info.get("class")
            if not model_class:
                skipped.append(name)
                continue

            try:
                result = model_class.load()

                if result.get("success"):
                    loaded.append(name)
                    cls._models[name]["last_loaded_at"] = time.time()
                else:
                    error = result.get("error", "unknown")
                    if skip_missing and error in (
                        "file_not_found",
                        "model_file_not_found",
                        "meta_file_not_found",
                    ):
                        skipped.append(name)
                    else:
                        failed.append({
                            "name": name,
                            "error": error,
                        })

            except Exception as e:
                failed.append({
                    "name": name,
                    "error": str(e),
                })

        cls._is_loaded = True
        cls._save_registry()

        logger.info(
            "registry_load_all_done",
            loaded=len(loaded),
            failed=len(failed),
            skipped=len(skipped),
        )

        return {
            "success": True,
            "loaded": loaded,
            "failed": failed,
            "skipped": skipped,
            "total": len(cls._models),
        }

    @classmethod
    def save_all(
        cls,
        *,
        only_trained: bool = True,
    ) -> Dict[str, Any]:
        """
        بيحفظ كل الموديلات المتدربة على disk.

        Args:
            only_trained: يحفظ بس الموديلات المتدربة؟

        Returns:
            dict فيه: saved, failed, skipped
        """
        saved = []
        failed = []
        skipped = []

        for name, info in cls._models.items():
            model_class = info.get("class")

            if not model_class:
                skipped.append(name)
                continue

            try:
                if only_trained and not model_class.is_trained():
                    skipped.append(name)
                    continue

                result = model_class.save()

                if result.get("success"):
                    saved.append(name)
                    cls._models[name]["last_saved_at"] = time.time()
                else:
                    failed.append({
                        "name": name,
                        "error": result.get("error", "unknown"),
                    })

            except Exception as e:
                failed.append({
                    "name": name,
                    "error": str(e),
                })

        cls._save_registry()

        logger.info(
            "registry_save_all_done",
            saved=len(saved),
            failed=len(failed),
            skipped=len(skipped),
        )

        return {
            "success": True,
            "saved": saved,
            "failed": failed,
            "skipped": skipped,
            "total": len(cls._models),
        }

    @classmethod
    def load_model(cls, name: str) -> Dict[str, Any]:
        """بيحمّل موديل واحد."""
        info = cls._models.get(name)
        if not info:
            return {
                "success": False,
                "error": "not_registered",
                "name": name,
            }

        try:
            result = info["class"].load()
            if result.get("success"):
                cls._models[name]["last_loaded_at"] = time.time()
                cls._save_registry()
            return result
        except Exception as e:
            logger.error("registry_load_model_failed", name=name, error=str(e))
            return {"success": False, "error": str(e)}

    @classmethod
    def save_model(cls, name: str) -> Dict[str, Any]:
        """بيحفظ موديل واحد."""
        info = cls._models.get(name)
        if not info:
            return {
                "success": False,
                "error": "not_registered",
                "name": name,
            }

        try:
            result = info["class"].save()
            if result.get("success"):
                cls._models[name]["last_saved_at"] = time.time()
                cls._save_registry()
            return result
        except Exception as e:
            logger.error("registry_save_model_failed", name=name, error=str(e))
            return {"success": False, "error": str(e)}

    # ═══════════════════════════════════════════════════════
    #  Delete
    # ═══════════════════════════════════════════════════════

    @classmethod
    def delete_model(cls, name: str) -> Dict[str, Any]:
        """بيمسح ملفات موديل + يشيله من الـ registry."""
        info = cls._models.get(name)
        if not info:
            return {
                "success": False,
                "error": "not_registered",
                "name": name,
            }

        deleted_files = False
        try:
            model_class = info.get("class")
            if model_class and hasattr(model_class, "delete_model"):
                deleted_files = model_class.delete_model()
        except Exception as e:
            logger.warning("registry_delete_files_failed", name=name, error=str(e))

        # شيله من الـ registry
        del cls._models[name]
        if cls._active_model == name:
            cls._active_model = None

        cls._save_registry()

        logger.info("model_deleted", name=name, files_deleted=deleted_files)

        return {
            "success": True,
            "name": name,
            "files_deleted": deleted_files,
        }

    @classmethod
    def reset_model(cls, name: str) -> Dict[str, Any]:
        """بيمسح الموديل من الـ memory (مش من disk)."""
        info = cls._models.get(name)
        if not info:
            return {
                "success": False,
                "error": "not_registered",
                "name": name,
            }

        try:
            model_class = info.get("class")
            if model_class and hasattr(model_class, "reset"):
                model_class.reset()

            logger.info("model_reset", name=name)

            return {"success": True, "name": name}

        except Exception as e:
            logger.error("registry_reset_model_failed", name=name, error=str(e))
            return {"success": False, "error": str(e)}

    @classmethod
    def reset_all(cls) -> Dict[str, Any]:
        """بيمسح كل الموديلات من الـ memory."""
        reset = []
        for name, info in cls._models.items():
            try:
                model_class = info.get("class")
                if model_class and hasattr(model_class, "reset"):
                    model_class.reset()
                    reset.append(name)
            except Exception as e:
                logger.warning("registry_reset_failed", name=name, error=str(e))

        cls._active_model = None

        logger.info("registry_reset_all", count=len(reset))

        return {
            "success": True,
            "reset": reset,
            "total": len(reset),
        }

    # ═══════════════════════════════════════════════════════
    #  Health Check
    # ═══════════════════════════════════════════════════════

    @classmethod
    def get_status(cls) -> Dict[str, Any]:
        """بيرجع حالة كل الموديلات."""
        status = {}

        for name, info in cls._models.items():
            model_class = info.get("class")

            entry: Dict[str, Any] = {
                "registered": True,
                "class_name": info.get("class_name"),
                "version": info.get("version"),
                "tags": info.get("tags", []),
                "is_active": name == cls._active_model,
                "is_trained": False,
                "has_stats": False,
                "error": None,
            }

            try:
                if model_class:
                    entry["is_trained"] = bool(model_class.is_trained())

                    if hasattr(model_class, "get_stats"):
                        stats = model_class.get_stats()
                        entry["has_stats"] = bool(stats)
                        entry["stats_keys"] = list(stats.keys())[:10]
            except Exception as e:
                entry["error"] = str(e)

            status[name] = entry

        trained = sum(1 for s in status.values() if s["is_trained"])
        errors = sum(1 for s in status.values() if s["error"])

        return {
            "total_models": len(cls._models),
            "trained_models": trained,
            "errored_models": errors,
            "active_model": cls._active_model,
            "models": status,
            "healthy": errors == 0,
        }

    @classmethod
    def health_check(cls) -> bool:
        """بترجع True لو كل الموديلات بصحة."""
        status = cls.get_status()
        return status["healthy"]

    # ═══════════════════════════════════════════════════════
    #  Utilities
    # ═══════════════════════════════════════════════════════

    @classmethod
    def get_models_by_tag(cls, tag: str) -> List[str]:
        """بيرجع الموديلات اللي عندها tag معين."""
        return [
            name for name, info in cls._models.items()
            if tag in info.get("tags", [])
        ]

    @classmethod
    def is_loaded(cls) -> bool:
        """بيتحقق لو الـ registry اتحمل من disk."""
        return cls._is_loaded

    @classmethod
    def clear(cls) -> None:
        """بيمسح كل الـ registry من الـ memory (مش من disk)."""
        cls._models = {}
        cls._active_model = None
        cls._is_loaded = False

        logger.info("registry_cleared")

    @classmethod
    def register_defaults(cls) -> Dict[str, Any]:
        """
        بيسجل كل الموديلات الافتراضية.

        Returns:
            dict فيه النتائج
        """
        results: Dict[str, Any] = {}

        try:
            from app.core.one_class_svm import OneClassSVMDetector
            results["svm"] = cls.register(
                "svm",
                OneClassSVMDetector,
                description="One-Class SVM anomaly detector",
                version="1.1",
                tags=["anomaly", "ml", "svm"],
                overwrite=True,
            )
        except Exception as e:
            results["svm"] = {"success": False, "error": str(e)}

        try:
            from app.core.lof_detector import LOFDetector
            results["lof"] = cls.register(
                "lof",
                LOFDetector,
                description="Local Outlier Factor anomaly detector",
                version="1.0",
                tags=["anomaly", "ml", "lof"],
                overwrite=True,
            )
        except Exception as e:
            results["lof"] = {"success": False, "error": str(e)}

        try:
            from app.core.ensemble_anomaly import EnsembleAnomalyDetector
            results["ensemble"] = cls.register(
                "ensemble",
                EnsembleAnomalyDetector,
                description="Multi-detector ensemble",
                version="1.0",
                tags=["anomaly", "ensemble"],
                overwrite=True,
            )
        except Exception as e:
            results["ensemble"] = {"success": False, "error": str(e)}

        try:
            from app.core.autoencoder import AutoencoderDetector
            results["autoencoder"] = cls.register(
                "autoencoder",
                AutoencoderDetector,
                description="Deep autoencoder anomaly detector",
                version="1.1",
                tags=["anomaly", "deep_learning"],
                overwrite=True,
            )
        except Exception as e:
            results["autoencoder"] = {"success": False, "error": str(e)}

        try:
            from app.core.lstm_model import LSTMModel
            results["lstm"] = cls.register(
                "lstm",
                LSTMModel,
                description="LSTM autoencoder for temporal anomaly detection",
                version="1.1",
                tags=["anomaly", "deep_learning", "temporal"],
                overwrite=True,
            )
        except Exception as e:
            results["lstm"] = {"success": False, "error": str(e)}

        try:
            from app.core.transformer_model import TransformerModel
            results["transformer"] = cls.register(
                "transformer",
                TransformerModel,
                description="Transformer autoencoder for temporal anomaly detection",
                version="1.0",
                tags=["anomaly", "deep_learning", "temporal", "attention"],
                overwrite=True,
            )
        except Exception as e:
            results["transformer"] = {"success": False, "error": str(e)}

        cls._save_registry()

        logger.info(
            "registry_defaults_registered",
            count=len(results),
            names=list(results.keys()),
        )

        return results


# ─── Standalone functions ─────────────────────────────

def register_model(name: str, model_class: Type, **kwargs) -> Dict[str, Any]:
    """Shortcut for ModelRegistry.register."""
    return ModelRegistry.register(name, model_class, **kwargs)


def list_models() -> List[str]:
    """Shortcut for ModelRegistry.list_models."""
    return ModelRegistry.list_models()


def load_all_models(**kwargs) -> Dict[str, Any]:
    """Shortcut for ModelRegistry.load_all."""
    return ModelRegistry.load_all(**kwargs)


def save_all_models(**kwargs) -> Dict[str, Any]:
    """Shortcut for ModelRegistry.save_all."""
    return ModelRegistry.save_all(**kwargs)


def get_registry_status() -> Dict[str, Any]:
    """Shortcut for ModelRegistry.get_status."""
    return ModelRegistry.get_status()