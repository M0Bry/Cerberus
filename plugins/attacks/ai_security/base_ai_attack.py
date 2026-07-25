"""Base AI Attack — Base class for AI security attack plugins."""

from plugins.core.base_attack import BaseAttack


class BaseAIAttack(BaseAttack):
    """Base class for AI security attacks."""

    def __init__(self):
        super().__init__()
        self.category = "ai_security"
