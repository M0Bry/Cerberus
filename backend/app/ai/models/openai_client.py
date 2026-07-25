"""OpenAI Client — GPT-4o/GPT-4-turbo integration with streaming support."""

import json
from collections.abc import AsyncIterator

import structlog
from openai import AsyncOpenAI

from app.core.config import settings

logger = structlog.get_logger()


class OpenAIClient:
    def __init__(self):
        self.client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)
        self.model = settings.OPENAI_MODEL

    async def chat(
        self,
        messages: list[dict],
        temperature: float = 0.7,
        max_tokens: int = 4096,
        json_mode: bool = False,
    ) -> str:
        kwargs = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}
        resp = await self.client.chat.completions.create(**kwargs)
        return resp.choices[0].message.content

    async def chat_stream(
        self, messages: list[dict], temperature: float = 0.7
    ) -> AsyncIterator[str]:
        stream = await self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=temperature,
            stream=True,
        )
        async for chunk in stream:
            if chunk.choices[0].delta.content:
                yield chunk.choices[0].delta.content

    async def chat_json(self, messages: list[dict], temperature: float = 0.3) -> dict:
        raw = await self.chat(messages, temperature=temperature, json_mode=True)
        return json.loads(raw)
