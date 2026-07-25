"""
API Keys Manager — Secure storage and retrieval of API keys.
"""

import os


class APIKeyManager:
    """
    Manages API keys for OSINT tools and services.

    Priority: Environment variables > Config file > Default (empty)
    """

    def __init__(self, config: dict | None = None):
        self.config = config or {}

    def get(self, service: str) -> str | None:
        """Get an API key for a service."""
        # Check environment first
        env_key = f"{service.upper().replace('-', '_')}_API_KEY"
        env_val = os.environ.get(env_key)
        if env_val:
            return env_val

        # Check config
        return self.config.get("api_keys", {}).get(service)

    def has_key(self, service: str) -> bool:
        """Check if an API key exists for a service."""
        return bool(self.get(service))

    def list_available(self) -> dict[str, str | None]:
        """List all configured API keys (masked)."""
        available: dict[str, str | None] = {}
        key_names = [
            "github_token", "shodan_api_key", "hunter_api_key",
            "telegram_api_id", "telegram_api_hash", "virustotal_api_key",
        ]
        for key_name in key_names:
            val = self.get(key_name)
            if val:
                available[key_name] = (
                    f"{val[:4]}...{val[-4:]}" if len(val) > 8 else "***"
                )
            else:
                available[key_name] = None
        return available
