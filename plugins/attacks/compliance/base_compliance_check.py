"""Base Compliance Check — Base class for compliance check plugins."""

from plugins.core.base_attack import BaseAttack


class BaseComplianceCheck(BaseAttack):
    """Base class for compliance checks."""

    def __init__(self):
        super().__init__()
        self.category = "compliance"
