"""Base Phishing Attack — Base class for phishing analysis plugins."""

from plugins.core.base_attack import BaseAttack


class BasePhishingAttack(BaseAttack):
    """Base class for phishing analysis operations."""

    def __init__(self):
        super().__init__()
        self.category = "phishing"
