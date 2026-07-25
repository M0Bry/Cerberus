"""AI Configuration — Model configs, temperature, max_tokens, API keys."""

import structlog

logger = structlog.get_logger()


AI_CONFIG = {
    "models": {
        "openai": {
            "primary": "gpt-4-turbo",
            "fallback": "gpt-3.5-turbo",
            "max_tokens": 4096,
            "temperature": 0.7,
        },
        "anthropic": {
            "primary": "claude-3-sonnet-20240229",
            "fallback": "claude-3-haiku-20240307",
            "max_tokens": 4096,
            "temperature": 0.7,
        },
    },
    "task_settings": {
        "conversation": {"temperature": 0.7, "max_tokens": 4096},
        "scope_generation": {"temperature": 0.3, "max_tokens": 4096, "json_mode": True},
        "osint_analysis": {"temperature": 0.3, "max_tokens": 4096},
        "attack_planning": {"temperature": 0.3, "max_tokens": 4096, "json_mode": True},
        "risk_assessment": {"temperature": 0.3, "max_tokens": 4096, "json_mode": True},
        "report_generation": {"temperature": 0.5, "max_tokens": 8192},
        "explain_decision": {"temperature": 0.5, "max_tokens": 2048},
        "defense_recommendation": {"temperature": 0.3, "max_tokens": 4096, "json_mode": True},
    },
    "context_window": {
        "max_tokens": 8000,
        "summary_threshold": 6000,
        "truncation_strategy": "sliding_window",
    },
}
