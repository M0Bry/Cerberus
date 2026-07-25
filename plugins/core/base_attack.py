"""
Base Attack Module - Abstract base class for all attack modules.
"""

import time
import uuid
from abc import ABC, abstractmethod
from collections.abc import AsyncGenerator
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .attack_context import AttackContext
from .attack_result import AttackResult, SeverityLevel
from .logger import CerberusLogger


class AttackStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"


@dataclass
class AttackConfig:
    timeout: int = 300
    threads: int = 10
    delay: float = 0.0
    retries: int = 3
    verify_ssl: bool = False
    user_agent: str = "Cerberus-AI/1.0"
    proxy: str | None = None
    custom_headers: dict[str, str] = field(default_factory=dict)


class BaseAttack(ABC):
    def __init__(self, config: AttackConfig | None = None):
        self.id = str(uuid.uuid4())
        self.config = config or AttackConfig()
        self.status = AttackStatus.PENDING
        self.logger = CerberusLogger(self.__class__.__name__)
        self.results: list[AttackResult] = []
        self.start_time: float | None = None
        self.end_time: float | None = None
        self._stopped = False

    @abstractmethod
    def get_name(self) -> str:
        ...

    @abstractmethod
    def get_description(self) -> str:
        ...

    @abstractmethod
    def get_category(self) -> str:
        ...

    @abstractmethod
    def get_severity(self) -> SeverityLevel:
        ...

    @abstractmethod
    async def run(self, context: AttackContext) -> AsyncGenerator[AttackResult, None]:
        """
        Main attack execution method.
        Yields AttackResult objects.
        """
        yield  # type: ignore[misc]

    async def execute(self, context: AttackContext) -> AsyncGenerator[AttackResult, None]:
        self.start_time = time.time()
        self.status = AttackStatus.RUNNING
        self.logger.info(f"Starting {self.get_name()} against {context.target}")

        try:
            async for result in self.run(context):
                if self._stopped:
                    break
                self.results.append(result)
                yield result
        except Exception as e:  # noqa: BLE001
            self.logger.error(f"Attack failed: {e!s}")
            self.status = AttackStatus.FAILED
            error_result = AttackResult(
                attack_name=self.get_name(),
                vulnerability_type="Execution Error",
                severity=SeverityLevel.ERROR,
                description=f"Attack execution failed: {e!s}",
                target=context.target,
                evidence=[],
                remediation="Review attack configuration and target availability",
            )
            self.results.append(error_result)
            yield error_result
        finally:
            self.end_time = time.time()
            if self.status != AttackStatus.FAILED:
                self.status = AttackStatus.COMPLETED
            self.logger.info(f"Attack completed in {self.get_duration():.2f}s")

    def get_duration(self) -> float:
        if self.start_time is None:
            return 0.0
        end = self.end_time or time.time()
        return end - self.start_time

    def stop(self):
        self._stopped = True
        self.logger.info("Attack stop signal received")

    def is_stopped(self) -> bool:
        return self._stopped

    def validate_context(self, context: AttackContext) -> bool:
        if not context.target:
            self.logger.error("No target specified in context")
            return False
        return True

    def get_metadata(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.get_name(),
            "description": self.get_description(),
            "category": self.get_category(),
            "severity": self.get_severity().value,
            "status": self.status.value,
            "duration": self.get_duration(),
            "result_count": len(self.results),
        }
