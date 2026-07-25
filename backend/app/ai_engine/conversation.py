"""
Cerberus AI Conversation Engine — Adaptive questioning and context building.
"""

import json

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
