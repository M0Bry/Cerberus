"""
Tier 3 — Generative AI Attack Prevention.

Generates virtual patches, updates firewall rules, and creates
automated defensive responses using AI.
"""

from datetime import datetime, timezone

import structlog
from openai import AsyncOpenAI

from app.core.config import settings

logger = structlog.get_logger()


class GenerativeDefense:
    """
    Tier 3: Generative AI Attack Prevention.

    Uses AI to analyze attack sequences, generate virtual patches,
    and create automated defensive responses.
    """

    def __init__(self) -> None:
        self.client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)
        self.model = settings.OPENAI_MODEL
        self.virtual_patches: list[dict] = []
        self.blocked_ips: set[str] = set()

    async def analyze_and_respond(
        self,
        session_id: str,
        client_ip: str,
        attack_sequence: list[dict],
        risk_score: float,
    ) -> dict:
        """
        Analyze a suspicious session and generate defensive response.

        Returns:
            Dict with 'actions_taken', 'virtual_patch', 'firewall_update', and 'alert'.
        """

        logger.info(
            "tier3_analysis_started",
            session_id=session_id,
            client_ip=client_ip,
            risk_score=risk_score,
        )

        # Generate virtual patch
        virtual_patch = await self._generate_virtual_patch(attack_sequence)

        # Block suspicious IP
        if risk_score > 0.8:
            self.blocked_ips.add(client_ip)

        # Generate security alert
        alert = self._generate_alert(
            session_id, client_ip, attack_sequence, risk_score
        )

        # Store virtual patch
        if virtual_patch:
            self.virtual_patches.append(virtual_patch)

        return {
            "actions_taken": [
                "virtual_patch_generated" if virtual_patch else None,
                "ip_blocked" if risk_score > 0.8 else None,
                "alert_generated",
            ],
            "virtual_patch": virtual_patch,
            "firewall_update": {
                "ip_blocked": client_ip if risk_score > 0.8 else None,
                "rules_updated": bool(virtual_patch),
            },
            "alert": alert,
        }

    async def _generate_virtual_patch(
        self, attack_sequence: list[dict]
    ) -> dict | None:
        """Generate a virtual patch to block the identified attack vector."""

        attack_summary = "\n".join(
            f"- {a.get('endpoint', 'N/A')}: {a.get('threat_type', 'unknown')}"
            for a in attack_sequence
        )

        prompt = f"""Based on the following attack sequence, generate a virtual patch
(a temporary security rule) that can block this attack vector.

Attack Sequence:
{attack_summary}

Generate a JSON object with:
1. rule_name: Descriptive name for the rule
2. rule_type: "waf_rule", "rate_limit", "ip_block", or "header_check"
3. pattern: The pattern to match/block
4. action: "block", "rate_limit", or "alert"
5. description: Human-readable description
6. ttl_hours: How long the rule should remain active"""

        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a security engineer generating WAF "
                            "virtual patches."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                max_tokens=1024,
                temperature=0.2,
                response_format={"type": "json_object"},
            )

            import json
            content = response.choices[0].message.content
            if content is None:
                logger.error("empty_response_content")
                return None
            patch = json.loads(content)
            patch["generated_at"] = datetime.now(timezone.utc).isoformat()  # noqa: UP017
            return patch

        except Exception as e:
            logger.error("virtual_patch_error", error=str(e))
            return None

    def _generate_alert(
        self,
        session_id: str,
        client_ip: str,
        attack_sequence: list[dict],
        risk_score: float,
    ) -> dict:
        """Generate a high-priority security alert."""
        return {
            "severity": "critical" if risk_score > 0.9 else "high",
            "title": f"Suspicious activity detected from {client_ip}",
            "description": (
                f"Session {session_id} triggered behavioral analysis with "
                f"risk score {risk_score:.2f}. Attack sequence includes "
                f"{len(attack_sequence)} suspicious activities."
            ),
            "source_ip": client_ip,
            "attack_types": list(
                set(a.get("threat_type") for a in attack_sequence)
            ),
            "recommended_actions": [
                "Review session logs",
                "Verify IP reputation",
                "Check for data exfiltration",
                "Update WAF rules if needed",
            ],
            "timestamp": datetime.now(timezone.utc).isoformat(),  # noqa: UP017
        }

    def is_ip_blocked(self, ip: str) -> bool:
        """Check if an IP is blocked."""
        return ip in self.blocked_ips

    def get_virtual_patches(self) -> list[dict]:
        """Get all active virtual patches."""
        return self.virtual_patches
