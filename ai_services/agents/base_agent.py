"""
Base Agent — Abstract base class for all AI agents.

All specialized agents inherit from this class and implement
the execute() method with their specific logic.
"""
from abc import ABC, abstractmethod
from typing import Any

import structlog

logger = structlog.get_logger()


class BaseAgent(ABC):
    """Base class for all Cerberus AI agents."""

    def __init__(self, name: str, description: str = "", capabilities: list[str] | None = None):
        self.name = name
        self.description = description
        self.capabilities = capabilities or []
        self.memory = None
        self.llm_client = None

    @abstractmethod
    async def execute(self, task_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Execute a task. Must be implemented by subclasses."""
        raise NotImplementedError

    async def think(self, context: str) -> str:
        """Chain-of-thought reasoning."""
        return f"[{self.name}] Analyzing: {context[:100]}..."

    async def reflect(self, result: dict[str, Any]) -> dict[str, Any]:
        """Self-reflection on task result."""
        return {"quality": 0.8, "improvements": []}

    async def store_memory(self, key: str, value: Any):
        """Store data in agent memory."""
        if self.memory:
            await self.memory.store(self.name, key, value)

    async def recall_memory(self, key: str) -> Any | None:
        """Recall data from agent memory."""
        if self.memory:
            return await self.memory.recall(self.name, key)
        return None
