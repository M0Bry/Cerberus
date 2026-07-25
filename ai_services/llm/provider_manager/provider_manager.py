"""
LLM Provider Manager — Manages multiple AI model providers.
"""

import structlog

logger = structlog.get_logger()


class LLMProvider:
    """Base class for an LLM provider."""

    def __init__(self, name: str, api_key: str | None = None):
        self.name = name
        self.api_key = api_key
        self.enabled = bool(api_key)

    async def generate(self, messages: list[dict], model: str | None = None, **kwargs) -> str:
        raise NotImplementedError


class ProviderManager:
    """
    Manages multiple LLM providers, with fallback and retry logic.
    """

    def __init__(self, config: dict[str, str] | None = None):
        config = config or {}
        self.providers: dict[str, LLMProvider] = {
            # In production: load from config
        }

    def add_provider(self, name: str, provider: LLMProvider) -> None:
        self.providers[name] = provider
        logger.info("provider_added", name=name)

    async def generate(self, messages: list[dict], task_type: str = "default", **kwargs) -> str:
        # Try preferred provider first
        for name, provider in self.providers.items():
            if provider.enabled:
                try:
                    logger.info("llm_request", provider=name, task=task_type)
                    return await provider.generate(messages, **kwargs)
                except Exception as e:  # noqa: BLE001
                    logger.warning("llm_provider_failed", provider=name, error=str(e))
                    continue

        # Fallback to any enabled provider
        for provider in self.providers.values():
            if provider.enabled:
                try:
                    return await provider.generate(messages, **kwargs)
                except Exception:
                    logger.exception("llm_provider_failed", provider=provider.name)
                    continue

        return "Error: No LLM provider available."
