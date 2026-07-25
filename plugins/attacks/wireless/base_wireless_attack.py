"""Base Wireless Attack — Base class for wireless attack plugins."""

from plugins.core.base_attack import BaseAttack


class BaseWirelessAttack(BaseAttack):
    """Base class for wireless security attacks."""

    def __init__(self):
        super().__init__()
        self.category = "wireless"
