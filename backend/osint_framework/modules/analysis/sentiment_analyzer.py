"""
Sentiment Analyzer — Analyzes sentiment in collected text data.
"""

import structlog

from osint_framework.core import IntelligenceResult
from osint_framework.plugins.plugin_manager import OSINTPlugin

logger = structlog.get_logger()


class SentimentAnalyzer(OSINTPlugin):
    """
    Analyzes sentiment in social media posts, forum mentions, and other text data.

    Features:
    - Positive/Negative/Neutral classification
    - Emotion detection
    - Threat level assessment
    - Trend analysis over time
    """

    def __init__(self):
        super().__init__()
        self.name = "sentiment_analyzer"
        self.description = "Text sentiment and threat analysis"
        self.category = "analysis"

    async def execute(self, target: str, **kwargs) -> IntelligenceResult | None:
        """Analyze sentiment in collected text data."""
        texts = kwargs.get("texts", [])
        logger.info("sentiment_analysis_started", texts=len(texts))

        # Simple keyword-based sentiment (in production: use VADER/TextBlob/LLM)
        threat_keywords = [
            "hack", "breach", "leak", "exploit", "vulnerability",
            "attack", "compromise",
        ]
        positive_keywords = [
            "secure", "protected", "patched", "updated", "compliant",
        ]

        results = []
        for text in texts:
            text_lower = text.lower() if isinstance(text, str) else ""
            threat_score = sum(1 for kw in threat_keywords if kw in text_lower)
            positive_score = sum(1 for kw in positive_keywords if kw in text_lower)

            if threat_score > positive_score:
                sentiment = "negative"
            elif positive_score > threat_score:
                sentiment = "positive"
            else:
                sentiment = "neutral"

            snippet = text[:200] if isinstance(text, str) else str(text)[:200]
            results.append({
                "text": snippet,
                "sentiment": sentiment,
                "threat_score": threat_score,
                "positive_score": positive_score,
            })

        overall = "neutral"
        neg_count = sum(1 for r in results if r["sentiment"] == "negative")
        pos_count = sum(1 for r in results if r["sentiment"] == "positive")
        if neg_count > len(results) * 0.5:
            overall = "negative"
        elif pos_count > len(results) * 0.5:
            overall = "positive"

        processed = {
            "total_texts": len(texts),
            "overall_sentiment": overall,
            "negative_count": neg_count,
            "results": results[:50],
        }

        return IntelligenceResult(
            source="sentiment_analyzer",
            data_type="sentiment_analysis",
            confidence=0.6,
            raw_data=results,
            processed_data=processed,
            category="employee",
            severity="high" if overall == "negative" and neg_count > 5 else "info",
            metadata={"texts_analyzed": len(texts)},
        )
