"""
Config Manager — Manages plugin configuration and API keys.
"""

import os
from typing import Any


class ConfigManager:
    """Manages configuration for the plugin system."""

    def __init__(self, config: dict[str, Any] | None = None):
        self._config = config or {}

    def get(self, key: str, default: Any = None) -> Any:
        """Get a config value by key."""
        env_val = os.environ.get(key.upper().replace(".", "_"))
        if env_val:
            return env_val
        return self._config.get(key, default)

    def get_api_key(self, service: str) -> str | None:
        """Get an API key for a service."""
        return self.get(f"api_keys.{service}")

    def has_api_key(self, service: str) -> bool:
        """Check if an API key exists."""
        return bool(self.get_api_key(service))
