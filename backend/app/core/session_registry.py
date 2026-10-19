"""
Session registry (Tier 2, Part D).

Closes the session-lifecycle gap: before Part D, logout was a no-op
and a leaked refresh token stayed usable for its full 7-day life.

Model:
* Every standard login mints a SESSION ID (``sid``) that is embedded
  in BOTH the access token and the refresh token.
* The registry tracks, per user:  sid -> {jti, created_at, ip, ua}
  where ``jti`` is the CURRENT refresh-token id (rotated on every
  refresh).
* ``is_active(user, sid)`` gates every authenticated request —
  logout's ``revoke`` kills the session immediately (access +
  refresh at once).
* ``rotate_jti`` enforces refresh-token rotation: presenting an
  already-rotated (old) refresh token fails the jti match and is
  rejected — a replay/hijack indicator.
* Per-user cap (SESSION_MAX_ACTIVE): the 6th login evicts the
  OLDEST session (its tokens die).

State is process-shared (class-level), the same pattern as the abuse
counters and cost budgets: service objects are instantiated per
request, so instance state would not work. In-memory is
authoritative (Redis is not running in this deployment); the
interface is deliberately storage-agnostic so a Redis backend can be
dropped in for multi-worker deployments.
"""

from __future__ import annotations

import hashlib
import threading
import time
from collections import OrderedDict
from typing import Dict, Optional

from app.core.config import settings


def hash_ua(user_agent: Optional[str]) -> Optional[str]:
    """Stable short fingerprint of the user agent (privacy: the raw
    UA string is never stored, only its hash)."""
    if not user_agent:
        return None
    return hashlib.sha256(user_agent[:200].encode()).hexdigest()[:12]


class SessionRegistry:
    """Per-user active-session tracking (class-level store)."""

    # user_id -> OrderedDict[sid -> entry]  (insertion order = age)
    _sessions: Dict[str, "OrderedDict[str, dict]"] = {}
    _lock = threading.Lock()

    @classmethod
    def _entry(cls, jti: str, ip: Optional[str], ua_hash: Optional[str]) -> dict:
        return {
            "jti": jti,
            "created_at": time.time(),
            "ip": ip,
            "ua": ua_hash,
        }

    @classmethod
    def register(
        cls,
        user_id: str,
        sid: str,
        jti: str,
        ip: Optional[str] = None,
        ua_hash: Optional[str] = None,
    ) -> Optional[str]:
        """Register a new session. Returns the sid of the EVICTED
        session when the per-user cap is exceeded (None otherwise)."""
        max_active = settings.SESSION_MAX_ACTIVE
        evicted: Optional[str] = None
        with cls._lock:
            sessions = cls._sessions.setdefault(user_id, OrderedDict())
            if sid not in sessions and len(sessions) >= max_active:
                evicted, _ = sessions.popitem(last=False)  # oldest
            sessions[sid] = cls._entry(jti, ip, ua_hash)
        return evicted

    @classmethod
    def is_active(cls, user_id: str, sid: str) -> bool:
        with cls._lock:
            return sid in cls._sessions.get(user_id, {})

    @classmethod
    def get_jti(cls, user_id: str, sid: str) -> Optional[str]:
        """The session's CURRENT refresh-token jti (None if the
        session is unknown)."""
        with cls._lock:
            entry = cls._sessions.get(user_id, {}).get(sid)
            return entry["jti"] if entry else None

    @classmethod
    def rotate_jti(cls, user_id: str, sid: str, new_jti: str) -> bool:
        """Rotate the session's refresh jti (called after a successful
        refresh). False if the session is unknown (revoked/evicted)."""
        with cls._lock:
            entry = cls._sessions.get(user_id, {}).get(sid)
            if entry is None:
                return False
            entry["jti"] = new_jti
            return True

    @classmethod
    def revoke(cls, user_id: str, sid: str) -> bool:
        """Logout: kill one session. Returns True if it existed."""
        with cls._lock:
            sessions = cls._sessions.get(user_id, {})
            if sid in sessions:
                del sessions[sid]
                if not sessions:
                    cls._sessions.pop(user_id, None)
                return True
            return False

    @classmethod
    def revoke_all(cls, user_id: str) -> int:
        """Kill every session of a user (admin action / compromise).
        Returns how many were active."""
        with cls._lock:
            n = len(cls._sessions.pop(user_id, ()))
            return n

    @classmethod
    def active_count(cls, user_id: str) -> int:
        with cls._lock:
            return len(cls._sessions.get(user_id, ()))

    @classmethod
    def active_sessions(cls, user_id: str) -> list[dict]:
        """Snapshot for the (future) 'active sessions' UI: sid, age,
        ip, ua fingerprint. Newest first."""
        with cls._lock:
            sessions = cls._sessions.get(user_id, OrderedDict())
            now = time.time()
            return [
                {
                    "sid": sid,
                    "age_seconds": int(now - e["created_at"]),
                    "ip": e["ip"],
                    "ua": e["ua"],
                }
                for sid, e in reversed(list(sessions.items()))
            ]

    @classmethod
    def reset_all(cls) -> None:
        """Test isolation / ops reset."""
        with cls._lock:
            cls._sessions.clear()
