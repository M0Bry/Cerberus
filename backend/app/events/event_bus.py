"""
Event Bus — Publish/subscribe event system.

Allows decoupled communication between services:
- Auth events (login, register, verify)
- Engagement events (created, status_changed, completed)
- OSINT events (finding_discovered, phase_completed)
- Security events (threat_detected, ip_blocked)
- Report events (generated, delivered)
"""

import asyncio
from collections.abc import Callable
from typing import Any

import structlog

logger = structlog.get_logger()


class EventBus:
    """Simple async event bus for service decoupling."""

    def __init__(self):
        self._handlers: dict[str, list[Callable]] = {}

    def subscribe(self, event_type: str, handler: Callable):
        """Subscribe a handler to an event type."""
        if event_type not in self._handlers:
            self._handlers[event_type] = []
        self._handlers[event_type].append(handler)

    async def publish(self, event_type: str, data: Any = None):
        """Publish an event to all subscribers."""
        logger.info("event_published", event_type=event_type)
        handlers = self._handlers.get(event_type, [])
        for handler in handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(data)
                else:
                    handler(data)
            except Exception as e:
                logger.error("event_handler_error", event=event_type, error=str(e))


# Global event bus instance
event_bus = EventBus()
