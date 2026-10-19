"""
Cerberus AI Conversation Engine — Adaptive questioning and context building.
"""

import json
import re

import structlog
from openai import AsyncOpenAI

from app.core.config import settings

logger = structlog.get_logger()

SYSTEM_PROMPT = (
    "You are Cerberus AI, an intelligent cybersecurity assistant. Your role is to "
    "guide clients through the penetration testing engagement setup process.\n\n"
    "Your responsibilities:\n"
    "1. Gather information about the organization, infrastructure, and security objectives\n"
    "2. Adapt your questions based on the organization type (financial, healthcare, tech, etc.)\n"
    "3. Identify critical assets, authorized testing targets, and out-of-scope systems\n"
    "4. Build a comprehensive understanding of the engagement requirements\n"
    "5. Ensure all legal and operational constraints are documented\n\n"
    "Guidelines:\n"
    "- Be professional, knowledgeable, and thorough\n"
    "- Ask one question at a time for clarity\n"
    "- Adapt follow-up questions based on previous answers\n"
    "- Focus on cybersecurity-relevant information\n"
    "- Never overwhelm the client with technical jargon\n"
    "- Ensure non-destructive testing is always the default\n\n"
    "Organization Type Context:\n"
    "- Financial: Focus on payment systems, transaction security, regulatory compliance (PCI-DSS)\n"
    "- Healthcare: Focus on patient data, HIPAA compliance, medical device security\n"
    "- Technology: Focus on web apps, APIs, cloud services, source code, containers\n"
    "- E-commerce: Focus on customer data, payment processing, web application security\n"
    "- Government: Focus on citizen data, compliance frameworks, critical infrastructure\n"
    "- General: Cover all common security assessment areas\n"
)


class CerberusAIConversation:
    """Handles AI-powered conversation for engagement setup."""

    def __init__(self) -> None:
        self.client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)
        self.model = settings.OPENAI_MODEL

    async def generate_response(
        self,
        history: list[dict],
        context: str | None = None,
        organization_type: str = "general",
    ) -> dict:
        """
        Generate an AI response based on conversation history.

        Args:
            history: List of message dicts with 'role' and 'content'.
            context: JSON string of the current context model.
            organization_type: Type of organization for adaptive questioning.

        Returns:
            Dict with 'response', 'follow_up_questions', and 'updated_context'.
        """

        # ── Scripted fallback ──────────────────────────────────────────
        # While AI models are not connected yet (no OPENAI_API_KEY), the
        # conversation runs on a natural, guided question flow so the full
        # product pipeline (chat → document → signature → operation) stays
        # testable end-to-end. Replacing this with the real model is a
        # one-line change: configure OPENAI_API_KEY.
        if not settings.OPENAI_API_KEY:
            return self._scripted_response(history, context)

        # Build messages for OpenAI
        messages = [
            {"role": "system", "content": self._build_system_prompt(organization_type)}
        ]

        # Add context if available
        if context:
            messages.append({
                "role": "system",
                "content": f"Current engagement context:\n{context}",
            })

        # Add conversation history
        for msg in history[-20:]:  # Last 20 messages for context window
            messages.append({
                "role": msg["role"],
                "content": msg["content"],
            })

        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=messages,  # type: ignore[arg-type]
                max_tokens=settings.OPENAI_MAX_TOKENS,
                temperature=0.7,
            )

            ai_message = response.choices[0].message.content
            if ai_message is None:
                ai_message = ""

            # Extract context updates
            updated_context = self._extract_context(ai_message, context)

            return {
                "response": ai_message,
                "updated_context": updated_context,
                "follow_up_questions": self._suggest_follow_ups(ai_message),
            }

        except Exception as e:
            logger.error("ai_conversation_error", error=str(e))
            return {
                "response": (
                    "I apologize, but I'm experiencing a temporary issue. "
                    "Please try again."
                ),
                "updated_context": None,
                "follow_up_questions": None,
            }

    # ─── Scripted fallback (used until the AI models are connected) ──
    #
    # A natural, non-pressuring conversation: the assistant talks to the
    # client like an experienced consultant, gathers five topics one by
    # one, then hands over the official document for signature.

    # The client's FIRST message is treated as the "organization" answer
    # (people naturally describe their setup when they open the chat), so
    # the scripted flow only asks the four follow-up questions below.
    _SCRIPTED_WELCOME = (
        "Hello, I'm Cerberus AI. Thanks for the introduction — that gives "
        "me a good first picture of your setup. We'll take this one step at "
        "a time; by the end I'll have the complete picture of your situation "
        "and exactly what I can do for you. "
    )

    _SCRIPTED_QUESTIONS: list[tuple[str, str]] = [
        (
            "objective",
            "Now — what's the main problem or goal behind this for you? "
            "What do you want us to check, or what are you worried about "
            "finding?",
        ),
        (
            "exclusions",
            "Understood. To keep everything safe, are there any systems, "
            "accounts, or environments that must absolutely never be "
            "touched? Think production payment systems, customer "
            "databases, third-party services — anything we should stay "
            "far away from.",
        ),
        (
            "timeframe",
            "Noted. When would you like this done? Is there a specific "
            "period in mind, or windows when testing should be avoided?",
        ),
        (
            "constraints",
            "Last one — any other constraints I should know about "
            "(legal, operational, technical)? Our default is fully "
            "non-destructive, proof-of-concept-level testing only. "
            "Is that what you're looking for?",
        ),
    ]

    _SCRIPTED_DOC_READY = (
        "Confirmed. I've prepared the official Scope of Engagement & "
        "Rules of Engagement document — it describes exactly what we "
        "will do, what is strictly off-limits, and the legal terms under "
        "which the work will happen. Review it below; when you're ready, "
        "type your full legal name to sign and authorize the engagement."
    )

    # The conversation has already produced the document: any further
    # message is answered in "authorized" mode — never re-fires the
    # document stage.
    _SCRIPTED_AUTHORIZED = (
        "Your engagement has been successfully authorized — the signed "
        "agreement is on file and the assessment is now active. The work "
        "proceeds automatically; you can follow its progress any time "
        "from the Notifications page."
    )

    # Words that mean "yes, that's correct" (EN + basic AR), used to end
    # the confirmation loop. Anything else is treated as a correction.
    _CONFIRM_RE = re.compile(
        r"\b(yes|yeah|yep|yup|correct|right|exactly|sure|ok|okay|okk|fine|"
        r"good|agreed|confirmed|perfect|ready|that'?s all|that'?s right|"
        r"sounds good|go ahead|proceed|تمام|ايوه|ايوا|اكيد|مؤكد|صح|كده|"
        r"ممتاز|طيب)\b",
        re.IGNORECASE,
    )

    # Starts with a negation -> the reply is a correction, no matter what
    # confirmation words it contains ("No, not correct" must not confirm).
    _NEGATE_RE = re.compile(
        r"^\s*(no|nope|not|incorrect|wrong|la|مش|لا)\b", re.IGNORECASE
    )

    def _scripted_summary(self, answers: dict, corrections: list[str]) -> str:
        """Plain-text confirmation summary of everything collected so far."""
        lines = [
            "Before I lock anything in, let me confirm my understanding of your situation:",
            "",
            f"• Your organization: {answers.get('organization', 'Not specified')}",
            f"• What you want from this: {answers.get('objective', 'Not specified')}",
            f"• Never to be touched: {answers.get('exclusions', 'Not specified')}",
            f"• Timeline: {answers.get('timeframe', 'Not specified')}",
            f"• Constraints: {answers.get('constraints', 'Not specified')}",
        ]
        for correction in corrections:
            lines.append(f"• Your correction: {correction}")
        lines.append("")
        lines.append(
            "Is this correct? If it is, I'll prepare the official Scope of "
            "Engagement & Rules of Engagement document. If anything is off, "
            "just tell me and I'll adjust."
        )
        return "\n".join(lines)

    def _scripted_response(self, history: list[dict], context: str | None) -> dict:
        """Guided question flow (no model required).

        State is kept in the engagement context under the "scripted" key:
        {"step": N, "answers": {...}, "corrections": [...],
         "stage": "questions" | "summary", "complete": bool}

        Flow: 5 natural questions -> the AI presents its understanding and
        asks "is this correct?" -> the client confirms (document is
        generated) or corrects (correction noted, understanding
        re-presented, loop continues until a confirmation arrives).
        """
        user_msgs = [m for m in history if m.get("role") == "user"]
        current = (user_msgs[-1]["content"] if user_msgs else "").strip()

        try:
            ctx = json.loads(context) if context else {}
        except (ValueError, TypeError):
            ctx = {}
        if not isinstance(ctx, dict):
            ctx = {}

        script = ctx.get("scripted")
        if not isinstance(script, dict):
            script = {}
        step = int(script.get("step", 0) or 0)
        answers = script.get("answers")
        if not isinstance(answers, dict):
            answers = {}
        corrections = script.get("corrections")
        if not isinstance(corrections, list):
            corrections = []
        # Link the mutable containers back to the script state so every
        # mutation below persists into the engagement context.
        script["answers"] = answers
        script["corrections"] = corrections
        stage = script.get("stage")
        if stage not in ("questions", "summary"):
            # Older contexts without a stage key: derive it from the step.
            stage = (
                "summary"
                if step >= len(self._SCRIPTED_QUESTIONS)
                else "questions"
            )

        total = len(self._SCRIPTED_QUESTIONS)

        # The document was already produced (client confirmed earlier):
        # answer in "authorized" mode and never re-fire the stage.
        if script.get("complete") and script.get("stage") == "summary":
            return {
                "response": self._SCRIPTED_AUTHORIZED,
                "updated_context": None,
                "follow_up_questions": None,
            }

        # --- STAGE: summary — the AI has presented its understanding and is
        # waiting for a confirmation (or one more correction).
        if stage == "summary":
            if self._NEGATE_RE.search(current):
                corrections.append(current)
                script["corrections"] = corrections
                ctx["scripted"] = script
                return {
                    "response": "Understood — correction noted. "
                    + self._scripted_summary(answers, corrections),
                    "updated_context": ctx,
                    "follow_up_questions": None,
                }
            if self._CONFIRM_RE.search(current):
                script["stage"] = "summary"
                script["complete"] = True
                ctx["scripted"] = script
                return {
                    "response": self._SCRIPTED_DOC_READY,
                    "updated_context": ctx,
                    "follow_up_questions": None,
                    "next_stage": "document",
                }
            corrections.append(current)
            script["corrections"] = corrections
            ctx["scripted"] = script
            return {
                "response": "Understood — correction noted. "
                + self._scripted_summary(answers, corrections),
                "updated_context": ctx,
                "follow_up_questions": None,
            }

        # --- STAGE: questions
        # Shortcut: the client signals they're done → fill the remaining
        # answers with defaults and jump to the confirmation summary.
        if step >= 1 and re.search(
            r"\b(that'?s all|thats all|done|skip)\b",
            current,
            re.IGNORECASE,
        ):
            for key, _ in self._SCRIPTED_QUESTIONS:
                answers.setdefault(key, "Not specified")
            script["step"] = total
            script["stage"] = "summary"
            ctx["scripted"] = script
            return {
                "response": self._scripted_summary(answers, corrections),
                "updated_context": ctx,
                "follow_up_questions": None,
            }

        if step == 0:
            # First user message = the organization answer (naturally
            # given when the user opens the chat). Greet + ask follow-up 1.
            answers["organization"] = current
            script["step"] = 1
            response = self._SCRIPTED_WELCOME + self._SCRIPTED_QUESTIONS[0][1]
        elif step < total:
            # Save the previous question's answer, ask the next one.
            answers[self._SCRIPTED_QUESTIONS[step - 1][0]] = current
            script["step"] = step + 1
            response = self._SCRIPTED_QUESTIONS[step][1]
        else:
            # Final answer received → present the understanding and ask for
            # confirmation (the document is NOT generated yet).
            answers[self._SCRIPTED_QUESTIONS[-1][0]] = current
            script["step"] = total
            script["stage"] = "summary"
            ctx["scripted"] = script
            return {
                "response": self._scripted_summary(answers, corrections),
                "updated_context": ctx,
                "follow_up_questions": None,
            }

        script["stage"] = "questions"
        ctx["scripted"] = script
        return {
            "response": response,
            "updated_context": ctx,
            "follow_up_questions": None,
        }

    async def generate_summary(
        self,
        history: list[dict],
        context: str | None = None,
    ) -> dict:
        """Generate a structured summary of the engagement requirements."""

        summary_prompt = (
            "Based on our conversation, generate a structured engagement summary with "
            "the following sections:\n\n"
            "1. organization_profile: Description of the organization\n"
            "2. business_objectives: Primary business objectives for this assessment\n"
            "3. critical_assets: Business-critical digital assets\n"
            "4. authorized_targets: Domains, IPs, applications authorized for testing\n"
            "5. out_of_scope: Systems explicitly excluded from testing\n"
            "6. expected_duration: Expected assessment duration\n"
            "7. security_priorities: Key security concerns and priorities\n"
            "8. technical_constraints: Operational and technical constraints\n"
            "9. compliance_considerations: Regulatory and compliance requirements\n"
            "10. potential_risks: Potential operational risks during assessment\n\n"
            "Format as JSON."
        )

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": summary_prompt},
        ]

        # Add conversation context
        for msg in history:
            messages.append({"role": msg["role"], "content": msg["content"]})

        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=messages,  # type: ignore[arg-type]
                max_tokens=settings.OPENAI_MAX_TOKENS,
                temperature=0.3,
                response_format={"type": "json_object"},  # type: ignore[call-overload]
            )

            return json.loads(response.choices[0].message.content)

        except Exception as e:
            logger.error("ai_summary_error", error=str(e))
            return {}

    def _build_system_prompt(self, organization_type: str) -> str:
        """Build context-aware system prompt."""
        context_addition = ""
        if organization_type == "financial":
            context_addition = (
                "\nThis is a FINANCIAL organization. Focus on PCI-DSS, "
                "transaction security, payment infrastructure, and regulatory compliance."
            )
        elif organization_type == "healthcare":
            context_addition = (
                "\nThis is a HEALTHCARE organization. Focus on HIPAA, "
                "patient data protection, medical devices, and clinical systems."
            )
        elif organization_type == "technology":
            context_addition = (
                "\nThis is a TECHNOLOGY organization. Focus on web applications, APIs, "
                "cloud infrastructure, container security, and CI/CD pipelines."
            )
        elif organization_type == "ecommerce":
            context_addition = (
                "\nThis is an E-COMMERCE organization. Focus on customer data, "
                "payment processing, web application security, and supply chain risks."
            )

        return SYSTEM_PROMPT + context_addition

    def _extract_context(
        self, ai_message: str, current_context: str | None
    ) -> str | None:
        """Extract and update context from the conversation."""
        # In production, use NLP to extract entities and update context
        return current_context

    def _suggest_follow_ups(self, ai_message: str) -> list[str] | None:
        """Suggest follow-up questions based on the AI response."""
        # In production, use AI to generate contextual follow-up suggestions
        return None
