"""Base Report — Base class for report generators."""

from plugins.core.base_attack import BaseAttack


class BaseReport(BaseAttack):
    """Base class for report generators."""

    def __init__(self):
        super().__init__()
        self.category = "reports"
