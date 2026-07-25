"""Base Cloud Attack — Base class for cloud attack plugins."""

from plugins.core.base_attack import BaseAttack


class BaseCloudAttack(BaseAttack):
    """Base class for cloud security attacks."""

    def __init__(self):
        super().__init__()
        self.category = "cloud"
