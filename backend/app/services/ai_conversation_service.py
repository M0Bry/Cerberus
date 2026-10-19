"""
AI Conversation Service — Manages the AI agent conversation for engagement setup.
"""

import json
import re
import uuid
from datetime import datetime, timezone

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai_engine.conversation import CerberusAIConversation
from app.ai_engine.roe_generator import RoEGenerator
from app.core.exceptions import NotFoundError
from app.db.models.engagement import Engagement, EngagementStatus
from app.db.models.rules_of_engagement import RulesOfEngagement
from app.db.models.scope import AssetType, ScopeAsset, ScopeOfEngagement
from app.schemas.ai_conversation import (
    ConversationHistoryResponse,
    ConversationMessageRequest,
    ConversationMessageResponse,
    ConversationSummaryResponse,
    MessageHistoryItem,
)

logger = structlog.get_logger()

# ─── Target extraction (pre-model heuristic) ──────────────────
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.IGNORECASE
)
_EXCLUDE_HINTS = (
    "never",
    "don't touch",
    "dont touch",
    "do not touch",
    "do not test",
    "out of scope",
    "out-of-scope",
    "exclude",
    "stay away",
    "avoid",
    "not touch",
    "no testing",
)


def _extract_targets(
    answers: dict, corrections: list[str] | None = None
) -> list[tuple[str, bool]]:
    """Pull explicit domains out of the conversation answers.

    Returns ``(value, is_excluded)`` pairs — a domain is flagged excluded
    when the client clearly marked it off-limits ("never touch X",
    "exclude X", …). Corrections from the confirm/correct loop are
    scanned too, so a correction changes the document. Until the AI
    models are connected this is a conservative heuristic; the real
    model will extract targets properly.
    """
    found: list[tuple[str, bool]] = []
    texts: list[str] = [
        answers.get(key) or ""
        for key in (
            "organization",
            "objective",
            "exclusions",
            "timeframe",
            "constraints",
            "intro",
        )
    ]
    texts.extend(corrections or [])
    for text in texts:
        lowered = text.lower()
        for match in _DOMAIN_RE.finditer(text):
            value = match.group(0).lower().rstrip(".")
            if value.startswith("www."):
                value = value[4:]
            if len(value) < 5 or "." not in value:
                continue
            # Skip obvious non-target words
            if value in {
                "e.g", "i.e", "www.com", "http.com", "https.com", "n.b", "p.o",
            }:
                continue
            excluded = False
            for hint in _EXCLUDE_HINTS:
                hint_idx = lowered.find(hint)
                domain_idx = lowered.find(value)
                if hint_idx != -1 and domain_idx != -1 and 0 <= domain_idx - hint_idx <= 60:
                    excluded = True
                    break
            if (value, excluded) not in found:
                found.append((value, excluded))
    return found


class AIConversationService:
    """Manages AI conversation for engagement requirement gathering."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.ai_engine = CerberusAIConversation()

    async def _get_engagement(self, engagement_id: str, user_id: str) -> Engagement:
        """Fetch engagement or raise error."""
        result = await self.db.execute(
            select(Engagement).where(
                Engagement.id == engagement_id,
                Engagement.user_id == user_id,
            )
        )
        engagement = result.scalar_one_or_none()
        if not engagement:
            raise NotFoundError("Engagement not found")
        return engagement

    async def process_message(
        self,
        engagement_id: str,
        user_id: str,
        payload: ConversationMessageRequest,
    ) -> ConversationMessageResponse:
        """Process a user message and generate AI response."""

        engagement = await self._get_engagement(engagement_id, user_id)

        # Load existing conversation history
        history = self._load_history(engagement)

        # Append user message
        history.append({
            "role": "user",
            "content": payload.message,
            "timestamp": datetime.now(timezone.utc).isoformat(),  # noqa: UP017
        })

        # Generate AI response using the engine
        ai_result = await self.ai_engine.generate_response(
            history=history,
            context=engagement.ai_context_model,
            organization_type=self._extract_org_type(history),
        )

        # Append AI response
        message_id = str(uuid.uuid4())
        history.append({
            "role": "assistant",
            "content": ai_result["response"],
            "timestamp": datetime.now(timezone.utc).isoformat(),  # noqa: UP017
        })

        # Save back to engagement
        engagement.conversation_history = json.dumps(history)
        if ai_result.get("updated_context"):
            engagement.ai_context_model = json.dumps(ai_result["updated_context"])

        # Conversation complete → prepare the official document
        # (Scope of Engagement + Rules of Engagement) for review & signature.
        next_stage = ai_result.get("next_stage")
        if next_stage == "document":
            await self._prepare_document(engagement)
        else:
            # The conversation has already produced the document, but its
            # preparation failed previously (fail-soft keeps the chat alive).
            # Retry it on any further message and re-surface the stage if
            # the retry succeeds, so the client is never left without its
            # document.
            ctx_now = (
                json.loads(engagement.ai_context_model)
                if engagement.ai_context_model
                else {}
            )
            script_now = (ctx_now or {}).get("scripted") or {}
            rules_exist = (
                await self.db.execute(
                    select(RulesOfEngagement.id).where(
                        RulesOfEngagement.engagement_id == engagement.id
                    )
                )
            ).scalar_one_or_none()
            if script_now.get("complete") and not rules_exist:
                await self._prepare_document(engagement)
                if (
                    await self.db.execute(
                        select(RulesOfEngagement.id).where(
                            RulesOfEngagement.engagement_id == engagement.id
                        )
                    )
                ).scalar_one_or_none():
                    next_stage = "document"
                    ai_result["response"] = (
                        "Confirmed. I've prepared the official Scope of "
                        "Engagement & Rules of Engagement document — it "
                        "describes exactly what we will do, what is "
                        "strictly off-limits, and the legal terms under "
                        "which the work will happen. Review it below; "
                        "when you're ready, type your full legal name to "
                        "sign and authorize the engagement."
                    )

        await self.db.flush()

        return ConversationMessageResponse(
            message_id=message_id,
            ai_response=ai_result["response"],
            follow_up_questions=ai_result.get("follow_up_questions"),
            context_updated=bool(ai_result.get("updated_context")),
            next_stage=next_stage,
        )

    # ─── Document preparation ───────────────────────────────────
    async def _prepare_document(self, engagement: Engagement) -> None:
        """Create the Scope of Engagement and generate the Rules of
        Engagement from the conversation context.

        Fail-soft: a failure here must not break the chat — the client can
        still retry through the rules endpoints.
        """
        try:
            ctx = json.loads(engagement.ai_context_model) if engagement.ai_context_model else {}
            script = (ctx or {}).get("scripted") or {}
            answers = script.get("answers") or {}
            corrections = script.get("corrections") or []

            scope = (
                await self.db.execute(
                    select(ScopeOfEngagement).where(
                        ScopeOfEngagement.engagement_id == engagement.id
                    )
                )
            ).scalar_one_or_none()

            if not scope:
                scope_summary = (
                    "Authorized, non-destructive security assessment of the "
                    f"client organization {engagement.organization_name or '(as described in the engagement conversation)'}."
                )
                if corrections:
                    # Client corrections from the confirmation loop are
                    # recorded on the face of the document.
                    scope_summary += " Client corrections on record: " + " ".join(
                        c.strip() for c in corrections if c.strip()
                    )
                scope = ScopeOfEngagement(
                    id=str(uuid.uuid4()),
                    engagement_id=engagement.id,
                    summary=scope_summary,
                    testing_objective=(
                        answers.get("objective")
                        or engagement.objective
                        or "Comprehensive security assessment"
                    ),
                    is_non_destructive=True,
                    include_osint=True,
                    include_red_team=True,
                    include_risk_assessment=True,
                    include_report_generation=True,
                )
                self.db.add(scope)
                await self.db.flush()

                for value, excluded in _extract_targets(answers, corrections):
                    self.db.add(
                        ScopeAsset(
                            id=str(uuid.uuid4()),
                            scope_id=scope.id,
                            asset_type=AssetType.DOMAIN,
                            value=value,
                            is_excluded=excluded,
                            exclusion_reason=(
                                "Marked out-of-scope by the client" if excluded else None
                            ),
                        )
                    )
            await self.db.flush()

            rules = (
                await self.db.execute(
                    select(RulesOfEngagement).where(
                        RulesOfEngagement.engagement_id == engagement.id
                    )
                )
            ).scalar_one_or_none()

            if not rules:
                asset_rows = (
                    await self.db.execute(
                        select(ScopeAsset).where(ScopeAsset.scope_id == scope.id)
                    )
                ).scalars().all()
                roe = await RoEGenerator().generate(
                    engagement=engagement,
                    scope=scope,
                    assets=list(asset_rows),
                )
                rules = RulesOfEngagement(
                    id=str(uuid.uuid4()),
                    engagement_id=engagement.id,
                    document_html=roe["html"],
                    document_text=roe["text"],
                    authorization_clause=roe["authorization"],
                    methodology_clause=roe["methodology"],
                    prohibited_actions_clause=roe["prohibited_actions"],
                    client_obligations_clause=roe["client_obligations"],
                    liability_clause=roe["liability"],
                    confidentiality_clause=roe["confidentiality"],
                )
                self.db.add(rules)
                engagement.status = EngagementStatus.RULES_GENERATED

            await self.db.flush()
            logger.info("document_prepared", engagement_id=engagement.id)
        except Exception as exc:  # noqa: BLE001 — never break the chat
            logger.warning(
                "document_preparation_failed", engagement_id=engagement.id, error=str(exc)
            )

    async def get_history(
        self, engagement_id: str, user_id: str
    ) -> ConversationHistoryResponse:
        """Get full conversation history."""
        engagement = await self._get_engagement(engagement_id, user_id)
        history = self._load_history(engagement)

        messages = [
            MessageHistoryItem(
                role=msg["role"],
                content=msg["content"],
                timestamp=datetime.fromisoformat(msg["timestamp"]),
            )
            for msg in history
        ]

        return ConversationHistoryResponse(
            engagement_id=engagement_id,
            messages=messages,
        )

    async def generate_summary(
        self, engagement_id: str, user_id: str
    ) -> ConversationSummaryResponse:
        """Generate AI summary of the engagement requirements."""
        engagement = await self._get_engagement(engagement_id, user_id)
        history = self._load_history(engagement)

        summary = await self.ai_engine.generate_summary(
            history=history,
            context=engagement.ai_context_model,
        )

        return ConversationSummaryResponse(
            engagement_id=engagement_id,
            organization_profile=summary.get("organization_profile", ""),
            business_objectives=summary.get("business_objectives", ""),
            critical_assets=summary.get("critical_assets", ""),
            authorized_targets=summary.get("authorized_targets", ""),
            out_of_scope=summary.get("out_of_scope", ""),
            expected_duration=summary.get("expected_duration", ""),
            security_priorities=summary.get("security_priorities", ""),
            technical_constraints=summary.get("technical_constraints", ""),
            compliance_considerations=summary.get("compliance_considerations", ""),
            potential_risks=summary.get("potential_risks", ""),
            is_confirmed=False,
        )

    async def confirm_summary(
        self, engagement_id: str, user_id: str
    ) -> dict:
        """Confirm summary and transition to scope generation."""
        engagement = await self._get_engagement(engagement_id, user_id)
        engagement.status = EngagementStatus.SCOPE_DEFINED
        await self.db.flush()

        return {
            "success": True,
            "message": "Summary confirmed. Scope of Engagement will be generated.",
            "next_step": "scope_generation",
        }

    def _load_history(self, engagement: Engagement) -> list[dict]:
        """Load conversation history from engagement."""
        if engagement.conversation_history:
            return json.loads(engagement.conversation_history)
        return []

    def _extract_org_type(self, history: list[dict]) -> str:
        """Extract organization type from conversation for adaptive questioning."""
        for msg in reversed(history):
            if msg["role"] == "user":
                content = msg["content"].lower()
                if any(w in content for w in ["bank", "financial", "fintech"]):
                    return "financial"
                if any(w in content for w in ["health", "hospital", "medical"]):
                    return "healthcare"
                if any(w in content for w in ["software", "dev", "tech", "saas"]):
                    return "technology"
                if any(w in content for w in ["ecommerce", "shop", "retail"]):
                    return "ecommerce"
        return "general"
