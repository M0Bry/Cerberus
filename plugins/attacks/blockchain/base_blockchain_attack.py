"""Base Blockchain Attack — Base class for blockchain attack plugins."""

from plugins.core.base_attack import BaseAttack


class BaseBlockchainAttack(BaseAttack):
    """Base class for blockchain security attacks."""

    def __init__(self):
        super().__init__()
        self.category = "blockchain"
