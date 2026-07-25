"""Base Mobile Attack — Base class for mobile attack plugins."""

from plugins.core.base_attack import BaseAttack


class BaseMobileAttack(BaseAttack):
    """Base class for mobile security attacks."""

    def __init__(self):
        super().__init__()
        self.category = "mobile"
