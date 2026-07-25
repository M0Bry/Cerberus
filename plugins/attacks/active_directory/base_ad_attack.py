"""Base AD Attack — Base class for Active Directory attack plugins."""

from plugins.core.base_attack import BaseAttack


class BaseADAttack(BaseAttack):
    """Base class for Active Directory attacks."""

    def __init__(self):
        super().__init__()
        self.category = "active_directory"
