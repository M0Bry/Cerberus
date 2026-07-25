"""Base Container Attack — Base class for container attack plugins."""

from plugins.core.base_attack import BaseAttack


class BaseContainerAttack(BaseAttack):
    """Base class for container security attacks."""

    def __init__(self):
        super().__init__()
        self.category = "containers"
