"""Output Filter — Filters harmful or sensitive content from AI outputs."""

import re

import structlog

logger = structlog.get_logger()


class OutputFilter:
    """Filters AI outputs for harmful, sensitive, or inappropriate content."""

    SENSITIVE_PATTERNS = [
        r"(password\s*[:=]\s*\S+)",
        r"(api[_-]?key\s*[:=]\s*\S+)",
        r"(secret\s*[:=]\s*\S+)",
        r"(token\s*[:=]\s*\S+)",
        r"(BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY)",
    ]

    def filter_output(self, text: str) -> str:
        """Filter sensitive data from AI output."""
        filtered = text
        for pattern in self.SENSITIVE_PATTERNS:
            filtered = re.sub(pattern, "[REDACTED]", filtered, flags=re.IGNORECASE)
        if filtered != text:
            logger.warning("output_filtered", original_length=len(text))
        return filtered

    def contains_sensitive_data(self, text: str) -> bool:
        """Check if text contains sensitive data patterns."""
        return any(
            re.search(pattern, text, re.IGNORECASE)
            for pattern in self.SENSITIVE_PATTERNS
        )
