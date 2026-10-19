"""
Tier 3 — Generative AI Defense.

Uses LLM (OpenAI / Anthropic) to generate virtual patches,
analyze unknown threats, and create automated defensive responses.

Features:
- Redis-backed storage (patches + blocked IPs)
- Mock Mode (when no API key is set)
- Multi-provider support (OpenAI + Anthropic)
- Caching (same attack → same patch)
- Rate limiting for LLM calls
"""

import hashlib
import json
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import redis.asyncio as redis
import structlog

from app.ai.prompts.system_prompt import (
    DEFENSE_VIRTUAL_PATCH_SYSTEM_PROMPT,
)
from app.core.config import settings

logger = structlog.get_logger()


class Tier3GenerativeDefense:
    """
    Tier 3: Generative AI Defense.

    بيستخدم LLM عشان:
    - يولد Virtual Patches
    - يحلل التهديدات الجديدة
    - يدعم Mock Mode (لو مفيش API key)
    - يخزن في Redis
    """

    _redis_client: Optional[redis.Redis] = None

    # Limits
    MAX_LLM_CALLS_PER_HOUR = 50

    def __init__(self) -> None:
        self.provider = settings.DEFENSE_LLM_PROVIDER.lower()
        self.model = settings.DEFENSE_LLM_MODEL
        self.mock_mode = self._is_mock_mode()
        self._openai_client = None
        self._anthropic_client = None

        if not self.mock_mode:
            self._init_clients()
        else:
            logger.warning(
                "tier3_mock_mode_enabled",
                reason="No valid API key configured",
            )

    # ─── Initialization ────────────────────────────────────

    @classmethod
    def get_redis(cls) -> Optional[redis.Redis]:
        """Lazy Redis initialization."""
        if cls._redis_client is None:
            try:
                cls._redis_client = redis.from_url(
                    settings.REDIS_URL,
                    decode_responses=True,
                    socket_connect_timeout=5,
                    socket_timeout=5,
                )
            except Exception as e:
                logger.error("tier3_redis_init_failed", error=str(e))
                return None
        return cls._redis_client

    def _is_mock_mode(self) -> bool:
        """بيفحص لو إحنا في Mock Mode."""
        if self.provider == "anthropic":
            key = settings.ANTHROPIC_API_KEY
            if not key or key.startswith("sk-ant-your"):
                return True
        else:  # openai
            key = settings.OPENAI_API_KEY
            if not key or key.startswith("sk-your"):
                return True
        return False

    def _init_clients(self) -> None:
        """بينشئ الـ LLM clients."""
        try:
            if self.provider == "anthropic":
                from anthropic import AsyncAnthropic
                self._anthropic_client = AsyncAnthropic(
                    api_key=settings.ANTHROPIC_API_KEY
                )
                logger.info("tier3_client_initialized", provider="anthropic")
            else:
                from openai import AsyncOpenAI
                self._openai_client = AsyncOpenAI(
                    api_key=settings.OPENAI_API_KEY
                )
                logger.info("tier3_client_initialized", provider="openai")
        except Exception as e:
            logger.error("tier3_client_init_failed", error=str(e))
            self.mock_mode = True

    # ─── Main API ──────────────────────────────────────────

    async def analyze_and_respond(
        self,
        session_id: str,
        client_ip: str,
        attack_sequence: List[Dict[str, Any]],
        risk_score: float,
    ) -> Dict[str, Any]:
        """
        بيحلل session مشبوه وبيولد رد دفاعي.

        Returns:
            dict فيه actions_taken, virtual_patch, firewall_update, alert
        """
        logger.info(
            "tier3_analysis_started",
            session_id=session_id,
            client_ip=client_ip,
            risk_score=risk_score,
            mock_mode=self.mock_mode,
        )

        # 1. تحقق من Rate Limit
        if not await self._check_llm_rate_limit():
            logger.warning("tier3_rate_limit_exceeded")
            return self._build_rate_limit_response(client_ip)

        # 2. حاول تجيب patch من الـ cache
        cache_key = self._build_cache_key(attack_sequence)
        virtual_patch = await self._get_cached_patch(cache_key)

        # 3. لو مش موجود، ولّد واحد جديد
        if not virtual_patch:
            virtual_patch = await self._generate_virtual_patch(attack_sequence)
            if virtual_patch:
                await self._cache_patch(cache_key, virtual_patch)

        # 4. خزّن الـ patch في Redis
        if virtual_patch:
            await self._store_patch(virtual_patch)

        # 5. احظر الـ IP لو risk عالي
        ip_blocked = False
        if risk_score > settings.DEFENSE_BLOCK_THRESHOLD:
            await self._block_ip(client_ip, duration=3600)
            ip_blocked = True

        # 6. ولّد الـ alert
        alert = self._generate_alert(
            session_id, client_ip, attack_sequence, risk_score
        )

        # 7. سجل الحادثة
        await self._record_tier3_incident(
            client_ip, virtual_patch, ip_blocked, risk_score
        )

        return {
            "actions_taken": [
                "virtual_patch_generated" if virtual_patch else None,
                "ip_blocked" if ip_blocked else None,
                "alert_generated",
            ],
            "virtual_patch": virtual_patch,
            "firewall_update": {
                "ip_blocked": client_ip if ip_blocked else None,
                "rules_updated": bool(virtual_patch),
            },
            "alert": alert,
            "mock_mode": self.mock_mode,
        }

    # ─── Virtual Patch Generation ─────────────────────────

    async def _generate_virtual_patch(
        self,
        attack_sequence: List[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """بيولد virtual patch باستخدام LLM أو Mock."""

        # Mock Mode
        if self.mock_mode:
            return self._generate_mock_patch(attack_sequence)

        # LLM Mode
        try:
            attack_summary = self._format_attack_sequence(attack_sequence)

            if self.provider == "anthropic":
                content = await self._call_anthropic(attack_summary)
            else:
                content = await self._call_openai(attack_summary)

            if not content:
                return None

            patch = json.loads(content)
            patch["generated_at"] = datetime.now(timezone.utc).isoformat()
            patch["provider"] = self.provider
            patch["model"] = self.model
            patch["mock"] = False

            logger.info("tier3_patch_generated", rule_name=patch.get("rule_name"))
            return patch

        except json.JSONDecodeError as e:
            logger.error("tier3_patch_json_error", error=str(e))
            return self._generate_mock_patch(attack_sequence)
        except Exception as e:
            logger.error("tier3_patch_error", error=str(e))
            return self._generate_mock_patch(attack_sequence)

    async def _call_openai(self, attack_summary: str) -> Optional[str]:
        """بيستدعي OpenAI."""
        if not self._openai_client:
            return None

        response = await self._openai_client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": DEFENSE_VIRTUAL_PATCH_SYSTEM_PROMPT},
                {"role": "user", "content": f"Attack Sequence:\n{attack_summary}"},
            ],
            max_tokens=settings.DEFENSE_LLM_MAX_TOKENS,
            temperature=settings.DEFENSE_LLM_TEMPERATURE,
            response_format={"type": "json_object"},
        )
        return response.choices[0].message.content

    async def _call_anthropic(self, attack_summary: str) -> Optional[str]:
        """بيستدعي Anthropic."""
        if not self._anthropic_client:
            return None

        response = await self._anthropic_client.messages.create(
            model=self.model,
            max_tokens=settings.ANTHROPIC_MAX_TOKENS,
            system=DEFENSE_VIRTUAL_PATCH_SYSTEM_PROMPT,
            messages=[
                {"role": "user", "content": f"Attack Sequence:\n{attack_summary}"},
            ],
        )
        return response.content[0].text

    def _generate_mock_patch(
        self,
        attack_sequence: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """بيولد patch ثابت (Mock Mode)."""
        # استخرج نوع الهجوم من الـ sequence
        attack_types = list(set(
            a.get("threat_type", "unknown")
            for a in attack_sequence
            if a.get("threat_type")
        ))
        attack_type = attack_types[0] if attack_types else "unknown"

        # اختار rule_type حسب نوع الهجوم
        rule_type_map = {
            "sql_injection": "waf_rule",
            "xss": "waf_rule",
            "command_injection": "waf_rule",
            "path_traversal": "waf_rule",
            "brute_force": "rate_limit",
            "scanning": "rate_limit",
        }
        rule_type = rule_type_map.get(attack_type, "waf_rule")

        return {
            "rule_name": f"mock_rule_{attack_type}",
            "rule_type": rule_type,
            "pattern": f"mock_pattern_{attack_type}",
            "action": "block",
            "description": f"Mock virtual patch for {attack_type}",
            "ttl_hours": 24,
            "confidence": 0.5,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "provider": "mock",
            "model": "mock",
            "mock": True,
        }

    # ─── Alert Generation ──────────────────────────────────

    def _generate_alert(
        self,
        session_id: str,
        client_ip: str,
        attack_sequence: List[Dict[str, Any]],
        risk_score: float,
    ) -> Dict[str, Any]:
        """بيولد security alert."""
        return {
            "severity": "critical" if risk_score > 0.9 else "high",
            "title": f"Suspicious activity from {client_ip}",
            "description": (
                f"Session {session_id} triggered Tier 3 with risk score "
                f"{risk_score:.2f}. {len(attack_sequence)} suspicious activities."
            ),
            "source_ip": client_ip,
            "attack_types": list(set(
                a.get("threat_type") for a in attack_sequence
                if a.get("threat_type")
            )),
            "recommended_actions": [
                "Review session logs",
                "Verify IP reputation",
                "Check for data exfiltration",
                "Update WAF rules if needed",
            ],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # ─── Redis Storage ─────────────────────────────────────

    async def _store_patch(self, patch: Dict[str, Any]) -> None:
        """بيخزن الـ patch في Redis."""
        client = self.get_redis()
        if not client:
            return

        try:
            key = f"tier3:patches:{patch.get('rule_name', 'unknown')}"
            patch_json = json.dumps(patch)
            ttl = int(patch.get("ttl_hours", 24)) * 3600

            await client.setex(key, ttl, patch_json)

            # ضيف للـ active patches list
            await client.sadd("tier3:active_patches", key)
            await client.expire("tier3:active_patches", ttl)

        except Exception as e:
            logger.error("tier3_store_patch_failed", error=str(e))

    async def _get_cached_patch(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """بيجيب patch من الـ cache."""
        client = self.get_redis()
        if not client:
            return None

        try:
            cached = await client.get(f"tier3:cache:{cache_key}")
            if cached:
                logger.info("tier3_patch_cache_hit")
                return json.loads(cached)
        except Exception as e:
            logger.error("tier3_cache_get_failed", error=str(e))
        return None

    async def _cache_patch(self, cache_key: str, patch: Dict[str, Any]) -> None:
        """بيخزن الـ patch في الـ cache."""
        client = self.get_redis()
        if not client:
            return

        try:
            await client.setex(
                f"tier3:cache:{cache_key}",
                3600,  # 1 hour cache
                json.dumps(patch),
            )
        except Exception as e:
            logger.error("tier3_cache_set_failed", error=str(e))

    async def _block_ip(self, ip: str, duration: int = 3600) -> None:
        """
        بيحظر IP عبر AbuseDetector (Redis + in-memory mirror),
        عشان أي مصدر حظر يستخدم نفس المخزن.
        """
        from app.core.abuse_detector import AbuseDetector

        try:
            await AbuseDetector.block_ip(ip, duration=duration)
            logger.warning("tier3_ip_blocked", ip=ip, duration=duration)
        except Exception as e:
            logger.error("tier3_block_ip_failed", error=str(e))

    async def _record_tier3_incident(
        self,
        ip: str,
        patch: Optional[Dict[str, Any]],
        ip_blocked: bool,
        risk_score: float,
    ) -> None:
        """بيسجل حادثة Tier 3."""
        from app.core.abuse_detector import AbuseDetector

        details = (
            f"Tier 3 response: risk={risk_score:.2f}, "
            f"patch={'yes' if patch else 'no'}, "
            f"ip_blocked={ip_blocked}"
        )
        await AbuseDetector.record_incident(ip, "tier3_response", details)

    # ─── Rate Limiting ─────────────────────────────────────

    async def _check_llm_rate_limit(self) -> bool:
        """بيفحص لو تعدينا حد الـ LLM calls."""
        if self.mock_mode:
            return True  # Mock Mode مش محتاج rate limit

        client = self.get_redis()
        if not client:
            return True

        try:
            key = f"tier3:llm_calls:{int(time.time() // 3600)}"
            count = await client.incr(key)
            if count == 1:
                await client.expire(key, 3600)

            return count <= self.MAX_LLM_CALLS_PER_HOUR
        except Exception as e:
            logger.error("tier3_rate_limit_check_failed", error=str(e))
            return True

    # ─── Utility ───────────────────────────────────────────

    def _build_cache_key(self, attack_sequence: List[Dict[str, Any]]) -> str:
        """ببني cache key من الـ attack sequence."""
        signatures = sorted([
            f"{a.get('endpoint', '')}:{a.get('threat_type', '')}"
            for a in attack_sequence
        ])
        text = "|".join(signatures)
        return hashlib.sha256(text.encode()).hexdigest()[:16]

    @staticmethod
    def _format_attack_sequence(attack_sequence: List[Dict[str, Any]]) -> str:
        """بيحول attack sequence لنص."""
        lines = []
        for a in attack_sequence[:20]:  # أول 20
            lines.append(
                f"- {a.get('endpoint', 'N/A')}: "
                f"{a.get('threat_type', 'unknown')} "
                f"(status={a.get('status_code', '?')})"
            )
        return "\n".join(lines)

    def _build_rate_limit_response(self, client_ip: str) -> Dict[str, Any]:
        """رد لما نتعدى rate limit."""
        return {
            "actions_taken": ["rate_limit_exceeded"],
            "virtual_patch": None,
            "firewall_update": {"ip_blocked": None, "rules_updated": False},
            "alert": {
                "severity": "medium",
                "title": "Tier 3 rate limit exceeded",
                "description": f"Too many LLM calls. Skipping analysis for {client_ip}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            "mock_mode": self.mock_mode,
        }

    # ─── Public Queries ────────────────────────────────────

    async def get_active_patches(self) -> List[Dict[str, Any]]:
        """بترجع كل الـ virtual patches النشطة."""
        client = self.get_redis()
        if not client:
            return []

        try:
            patch_keys = await client.smembers("tier3:active_patches")
            patches = []
            for key in patch_keys:
                patch_json = await client.get(key)
                if patch_json:
                    try:
                        patches.append(json.loads(patch_json))
                    except json.JSONDecodeError:
                        continue
            return patches
        except Exception as e:
            logger.error("tier3_get_patches_failed", error=str(e))
            return []

    async def clear_patches(self) -> None:
        """بتمسح كل الـ patches."""
        client = self.get_redis()
        if not client:
            return

        try:
            patch_keys = await client.smembers("tier3:active_patches")
            if patch_keys:
                await client.delete(*patch_keys)
            await client.delete("tier3:active_patches")
            logger.info("tier3_patches_cleared")
        except Exception as e:
            logger.error("tier3_clear_patches_failed", error=str(e))

    @classmethod
    async def close(cls) -> None:
        """بتقفل Redis."""
        if cls._redis_client:
            await cls._redis_client.close()
            cls._redis_client = None