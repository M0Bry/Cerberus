"""
Logging Module - Structured logging for Cerberus framework
"""

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, ClassVar


class CerberusFormatter(logging.Formatter):
    """Custom formatter for structured logging"""

    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }

        # Add extra fields if present
        if hasattr(record, "attack_id"):
            log_data["attack_id"] = record.attack_id
        if hasattr(record, "target"):
            log_data["target"] = record.target
        if hasattr(record, "engagement_id"):
            log_data["engagement_id"] = record.engagement_id

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_data)


class CerberusLogger:
    """
    Wrapper around Python logging for Cerberus-specific functionality

    Provides structured logging with attack context tracking
    """

    _initialized: ClassVar[bool] = False
    _handlers: ClassVar[list[logging.Handler]] = []

    def __init__(self, name: str, level: int = logging.INFO):
        self.logger = logging.getLogger(f"cerberus.{name}")
        self.logger.setLevel(level)

        # Setup handlers if not already done
        if not CerberusLogger._initialized:
            self._setup_handlers()
            CerberusLogger._initialized = True

        # Add handlers if not present
        for handler in CerberusLogger._handlers:
            if handler not in self.logger.handlers:
                self.logger.addHandler(handler)

    def _setup_handlers(self):
        """Setup default logging handlers"""
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        console_handler.setFormatter(console_formatter)
        CerberusLogger._handlers.append(console_handler)

        # File handler for JSON logs
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        file_handler = logging.FileHandler(log_dir / "cerberus.json")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(CerberusFormatter())
        CerberusLogger._handlers.append(file_handler)

    def debug(self, msg: str, extra: dict[str, Any] | None = None):
        """Log debug message"""
        self.logger.debug(msg, extra=extra or {})

    def info(self, msg: str, extra: dict[str, Any] | None = None):
        """Log info message"""
        self.logger.info(msg, extra=extra or {})

    def warning(self, msg: str, extra: dict[str, Any] | None = None):
        """Log warning message"""
        self.logger.warning(msg, extra=extra or {})

    def error(self, msg: str, extra: dict[str, Any] | None = None):
        """Log error message"""
        self.logger.error(msg, extra=extra or {})

    def critical(self, msg: str, extra: dict[str, Any] | None = None):
        """Log critical message"""
        self.logger.critical(msg, extra=extra or {})

    def exception(self, msg: str, exc_info: bool = True):
        """Log exception with traceback"""
        self.logger.exception(msg, exc_info=exc_info)

    def attack_log(self, attack_name: str, target: str,
                   status: str, details: dict[str, Any] | None = None):
        """
        Log attack-specific information

        Args:
            attack_name: Name of the attack
            target: Target being attacked
            status: Attack status
            details: Additional details
        """
        extra = {
            "attack_name": attack_name,
            "target": target,
            "status": status,
            **(details or {})
        }
        self.info(f"Attack [{attack_name}] on {target}: {status}", extra=extra)
