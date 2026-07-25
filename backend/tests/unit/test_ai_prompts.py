"""AI prompt rendering + output validation."""

from app.ai.prompts.system_prompt import INTAKE_PROMPT, SYSTEM_PROMPT


def test_system_prompt_exists():
    assert len(SYSTEM_PROMPT) > 100


def test_intake_prompt_exists():
    assert "organization" in INTAKE_PROMPT.lower()
