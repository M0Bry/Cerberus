"""In-Memory Store — bounded single-process fallback for the defense layer.

The defense stack is Redis-first so it scales across multiple workers.
In single-process environments (local dev, sandboxes, or when Redis is
down) the same behavior must still hold — but silently dropping to
"always allow" (fail-open only) would leave the API undefended.

This module provides small, bounded, asyncio-safe in-memory structures
with exactly the semantics the Redis-backed components need:

- SlidingWindowCounter  → per-key request windows (rate limiting)
- WindowedEventLog      → per-key event timestamps (abuse counters)
- ExpiringKeySet        → per-key blocklists with TTL (IP blocks)

All structures cap their memory (max keys / max entries per key) and
prune lazily on access, so they are safe to keep for the lifetime of
the process.
"""

import time
from collections import deque
from typing import Deque, Dict, List, Optional, Tuple


class SlidingWindowCounter:
    """Counts events per key within a rolling time window.

    check() is atomic within a single event loop (no await between
    read and write), so it is safe under concurrent asyncio tasks.
    """

    def __init__(self, max_keys: int = 10_000) -> None:
        self._windows: Dict[str, Deque[float]] = {}
        self._max_keys = max_keys

    def _prune(self, key: str, now: float, window: float) -> None:
        dq = self._windows.get(key)
        if not dq:
            return
        cutoff = now - window
        while dq and dq[0] <= cutoff:
            dq.popleft()

    def check(
        self,
        key: str,
        limit: int,
        window: float,
        now: Optional[float] = None,
    ) -> dict:
        """Record the current request and report allow/block.

        Returns:
            {"allowed": bool, "remaining": int, "limit": int,
             "retry_after": int}
        """
        now = time.time() if now is None else now
        dq = self._windows.get(key)
        if dq is None:
            if len(self._windows) >= self._max_keys:
                # Evict the coldest window to stay bounded.
                self._windows.pop(next(iter(self._windows)), None)
            dq = self._windows[key] = deque()
        else:
            self._prune(key, now, window)

        count = len(dq)
        if count < limit:
            dq.append(now)
            return {
                "allowed": True,
                "remaining": limit - count - 1,
                "limit": limit,
                "retry_after": 0,
            }
        # Compute how long until the oldest entry leaves the window.
        retry_after = max(1, int(dq[0] + window - now)) if dq else int(window)
        return {
            "allowed": False,
            "remaining": 0,
            "limit": limit,
            "retry_after": retry_after,
        }

    def count(self, key: str, window: float, now: Optional[float] = None) -> int:
        now = time.time() if now is None else now
        dq = self._windows.get(key)
        if not dq:
            return 0
        self._prune(key, now, window)
        return len(dq)

    def clear(self, key: str) -> None:
        self._windows.pop(key, None)

    def reset_all(self) -> None:
        self._windows.clear()


class WindowedEventLog:
    """Per-key log of event timestamps within a rolling window.

    Mirrors the abuse-detector's Redis list semantics: record() appends
    and returns the in-window count; count() reads without appending.
    """

    def __init__(self, max_keys: int = 10_000, max_entries_per_key: int = 1000) -> None:
        self._logs: Dict[str, Deque[float]] = {}
        self._max_keys = max_keys
        self._max_entries = max_entries_per_key

    def _prune(self, key: str, now: float, window: float) -> Deque[float]:
        dq = self._logs[key]
        cutoff = now - window
        while dq and dq[0] <= cutoff:
            dq.popleft()
        return dq

    def record(self, key: str, window: float, now: Optional[float] = None) -> int:
        now = time.time() if now is None else now
        dq = self._logs.get(key)
        if dq is None:
            if len(self._logs) >= self._max_keys:
                self._logs.pop(next(iter(self._logs)), None)
            dq = self._logs[key] = deque()
        self._prune(key, now, window)
        dq.append(now)
        while len(dq) > self._max_entries:
            dq.popleft()
        return len(dq)

    def count(self, key: str, window: float, now: Optional[float] = None) -> int:
        now = time.time() if now is None else now
        dq = self._logs.get(key)
        if not dq:
            return 0
        self._prune(key, now, window)
        return len(dq)

    def count_prefix(self, prefix: str, window: float, now: Optional[float] = None) -> int:
        """Sum in-window counts across all keys sharing a prefix."""
        now = time.time() if now is None else now
        total = 0
        for key, dq in list(self._logs.items()):
            if not key.startswith(prefix):
                continue
            cutoff = now - window
            while dq and dq[0] <= cutoff:
                dq.popleft()
            if not dq:
                self._logs.pop(key, None)
                continue
            total += len(dq)
        return total

    def remove(self, key: str) -> None:
        self._logs.pop(key, None)

    def reset_all(self) -> None:
        self._logs.clear()


class ExpiringKeySet:
    """A set of blocked keys with per-key TTL (mirrors Redis EXPIRE)."""

    def __init__(self, max_keys: int = 10_000) -> None:
        self._entries: Dict[str, float] = {}  # key -> expires_at (unix)
        self._max_keys = max_keys

    def _prune_expired(self, now: float) -> None:
        expired = [k for k, exp in self._entries.items() if exp <= now]
        for k in expired:
            del self._entries[k]

    def add(self, key: str, ttl: int, now: Optional[float] = None) -> None:
        now = time.time() if now is None else now
        if len(self._entries) >= self._max_keys and key not in self._entries:
            self._prune_expired(now)
            if len(self._entries) >= self._max_keys:
                self._entries.pop(next(iter(self._entries)), None)
        self._entries[key] = now + ttl

    def is_blocked(self, key: str, now: Optional[float] = None) -> bool:
        now = time.time() if now is None else now
        exp = self._entries.get(key)
        if exp is None:
            return False
        if exp <= now:
            del self._entries[key]
            return False
        return True

    def seconds_remaining(self, key: str, now: Optional[float] = None) -> int:
        now = time.time() if now is None else now
        exp = self._entries.get(key, 0.0)
        return max(0, int(exp - now))

    def remove(self, key: str) -> None:
        self._entries.pop(key, None)

    def all_blocked(self, now: Optional[float] = None) -> List[Tuple[str, int]]:
        now = time.time() if now is None else now
        self._prune_expired(now)
        return [(k, max(0, int(exp - now))) for k, exp in self._entries.items()]

    def reset_all(self) -> None:
        self._entries.clear()
