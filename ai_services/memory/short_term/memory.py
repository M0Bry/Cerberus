"""Short-term memory — In-memory buffer for current conversation context."""
from typing import Any

import structlog

logger = structlog.get_logger()


class ShortTermMemory:
    """Fast, ephemeral memory for current session context."""

    def __init__(self, max_items: int = 100):
        self._store: dict[str, list[dict]] = {}
        self.max_items = max_items

    async def store(self, session_id: str, key: str, value: Any):
        if session_id not in self._store:
            self._store[session_id] = []
        self._store[session_id].append({"key": key, "value": value})
        if len(self._store[session_id]) > self.max_items:
            self._store[session_id] = self._store[session_id][-self.max_items:]

    async def recall(self, session_id: str, key: str) -> Any | None:
        for item in self._store.get(session_id, []):
            if item["key"] == key:
                return item["value"]
        return None

    async def get_all(self, session_id: str) -> list[dict]:
        return self._store.get(session_id, [])

    async def clear(self, session_id: str):
        self._store.pop(session_id, None)
