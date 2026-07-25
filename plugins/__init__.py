"""
Cerberus Attack Framework - Main Package
Intelligent Penetration Testing Platform
"""

__version__ = "1.0.0"
__author__ = "Cerberus AI"
__license__ = "Proprietary"

from .core.attack_context import AttackContext
from .core.attack_result import (
    AttackEvidence,
    AttackResult,
    ConfidenceLevel,
    SeverityLevel,
)
from .core.base_attack import AttackConfig, AttackStatus, BaseAttack
from .core.plugin_manager import PluginManager

__all__ = [
    "AttackConfig",
    "AttackContext",
    "AttackEvidence",
    "AttackResult",
    "AttackStatus",
    "BaseAttack",
    "ConfidenceLevel",
    "PluginManager",
    "SeverityLevel",
]
