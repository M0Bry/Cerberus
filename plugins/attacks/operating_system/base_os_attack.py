"""Base OS Attack — Base class for operating system attack plugins."""

from plugins.core.base_attack import BaseAttack


class BaseOSAttack(BaseAttack):
    """Base class for OS-level attacks."""

    def __init__(self):
        super().__init__()
        self.category = "operating_system"
