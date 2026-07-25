"""Model Router — Routes tasks to the best available AI model."""

import structlog

from app.ai.models.anthropic_client import AnthropicClient
from app.ai.models.openai_client import OpenAIClient
from app.core.config import settings

logger = structlog.get_logger()

# Task → Model mapping
TASK_MODEL_MAP = {
    "conversation": "openai",
    "scope_generation": "openai",
    "osint_analysis": "openai",
    "attack_planning": "openai",
    "risk_assessment": "openai",
    "report_generation": "openai",
    "explain_decision": "openai",
    "defense_recommendation": "openai",
}


class ModelRouter:
    """Routes AI tasks to the best model based on task type and availability."""

    def __init__(self):
        self.openai = OpenAIClient()
        self.anthropic = AnthropicClient(api_key=getattr(settings, "ANTHROPIC_API_KEY", ""))

    def get_client(self, task_type: str = "conversation"):
        provider = TASK_MODEL_MAP.get(task_type, "openai")
        if provider == "anthropic" and self.anthropic.api_key:
            return self.anthropic
        return self.openai

    async def generate(self, task_type: str, messages: list[dict], **kwargs) -> str:
        client = self.get_client(task_type)
        logger.info("ai_request", task=task_type, model=client.__class__.__name__)
        return await client.chat(messages, **kwargs)

    async def generate_json(self, task_type: str, messages: list[dict], **kwargs) -> dict:
        client = self.get_client(task_type)
        if isinstance(client, OpenAIClient):
            return await client.chat_json(messages, **kwargs)
        raw = await client.chat(messages, **kwargs)
        import json
        return json.loads(raw)


model_router = ModelRouter()
