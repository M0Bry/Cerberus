"""
Plugin Decorators — Utility decorators for attack modules.
"""

import functools
import time
from collections.abc import Callable


def timed(func: Callable) -> Callable:
    """Decorator to measure execution time of an attack method."""
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        start = time.time()
        result = await func(*args, **kwargs)
        if hasattr(result, "duration_ms"):
            result.duration_ms = (time.time() - start) * 1000
        return result
    return wrapper


def requires_auth(func: Callable) -> Callable:
    """Decorator to mark a method as requiring authentication."""
    @functools.wraps(func)
    async def wrapper(self, target, context, *args, **kwargs):
        if context and not context.auth_token:
            from plugins.core.attack_result import AttackResult, AttackStatus
            return AttackResult(
                plugin_name=self.name,
                target=target,
                status=AttackStatus.SKIPPED,
                title="Authentication required",
                description="This attack requires authentication to execute.",
            )
        return await func(self, target, context, *args, **kwargs)
    return wrapper


def non_destructive(func: Callable) -> Callable:
    """Decorator to mark an attack as non-destructive."""
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        return await func(*args, **kwargs)
    wrapper._non_destructive = True  # type: ignore[attr-defined]
    return wrapper
