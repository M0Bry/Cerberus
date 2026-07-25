"""
OSINT Framework Settings — Configuration management.
"""

import os
from typing import Any

import yaml  # type: ignore[import-untyped]

# (the rest of the file is identical to the last clean version)

DEFAULT_CONFIG = {
    "api_keys": {
        "github_token": "",
        "shodan_api_key": "",
        "hunter_api_key": "",
        "telegram_api_id": "",
        "telegram_api_hash": "",
        "virustotal_api_key": "",
    },
    "neo4j": {
        "uri": "bolt://localhost:7687",
        "user": "neo4j",
        "password": "password",
    },
    "tor": {
        "socks_port": 9050,
        "control_port": 9051,
        "password": "",
    },
    "plugins": {
        "enabled": [
            "username_enum",
            "social_scanner",
            "image_analyzer",
            "domain_intel",
            "github_scan",
            "shodan_search",
            "tor_scrape",
            "telegram_monitor",
            "network_analyzer",
            "sentiment_analyzer",
        ],
        "settings": {
            "max_concurrent_scans": 10,
            "request_delay": 1.0,
            "timeout": 30,
            "retry_attempts": 3,
        },
    },
    "analysis": {
        "risk_threshold": 0.7,
        "confidence_threshold": 0.6,
        "max_network_size": 1000,
    },
    "reporting": {
        "output_format": "json",
        "include_raw_data": False,
        "encrypt_report": False,
        "retention_days": 90,
    },
    "security": {
        "verify_ssl": True,
        "anonymize_requests": False,
        "rotate_user_agents": True,
    },
}


def load_config(config_path: str | None = None) -> dict[str, Any]:
    """Load configuration from file, falling back to defaults."""
    config = DEFAULT_CONFIG.copy()

    if config_path and os.path.exists(config_path):
        with open(config_path) as f:
            file_config = yaml.safe_load(f)
            if file_config:
                _deep_merge(config, file_config)

    # Override with environment variables
    env_overrides = {
        "GITHUB_TOKEN": ("api_keys", "github_token"),
        "SHODAN_API_KEY": ("api_keys", "shodan_api_key"),
        "HUNTER_API_KEY": ("api_keys", "hunter_api_key"),
        "TELEGRAM_API_ID": ("api_keys", "telegram_api_id"),
        "TELEGRAM_API_HASH": ("api_keys", "telegram_api_hash"),
    }

    for env_key, config_path_tuple in env_overrides.items():
        env_val = os.environ.get(env_key)
        if env_val:
            section, key = config_path_tuple
            config[section][key] = env_val  # type: ignore[index]

    return config


def _deep_merge(base: dict, override: dict) -> None:
    """Deep merge override into base dict."""
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
