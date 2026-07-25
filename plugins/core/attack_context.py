"""  
Attack Context Module - Execution context for attacks  
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class TargetInfo:
    """Information about the target"""
    url: str | None = None
    ip: str | None = None
    domain: str | None = None
    port: int | None = None
    protocol: str = "https"
    service: str | None = None
    version: str | None = None
    technologies: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)

    def get_base_url(self) -> str:
        """Get base URL for target"""
        if self.url:
            return self.url
        if self.domain:
            return f"{self.protocol}://{self.domain}"
        if self.ip:
            return f"{self.protocol}://{self.ip}"
        return ""

    def get_full_url(self, path: str = "") -> str:
        """Get full URL with optional path"""
        base = self.get_base_url()
        if not base:
            return ""
        if path:
            return f"{base.rstrip('/')}/{path.lstrip('/')}"
        return base


@dataclass
class ScopeConfig:
    """Scope of engagement configuration"""
    allowed_targets: list[str] = field(default_factory=list)
    excluded_targets: list[str] = field(default_factory=list)
    allowed_ports: list[int] = field(default_factory=lambda: [80, 443, 8080])
    excluded_ports: list[int] = field(default_factory=list)
    allow_destructive: bool = False
    max_impact: str = "proof_of_concept"  # proof_of_concept, limited, full
    testing_window: dict[str, Any] | None = None  # start/end times

    def is_in_scope(self, target: str) -> bool:
        """Check if target is in scope"""
        # Check exclusions first
        for excluded in self.excluded_targets:
            if excluded in target:
                return False

        # Check allowed targets
        if not self.allowed_targets:
            return True  # If no restrictions, allow all

        for allowed in self.allowed_targets:
            if allowed in target:
                return True

        return False


@dataclass
class AttackContext:
    """
    Context object passed to all attack modules

    Contains all information needed for attack execution including
    target details, authentication, scope, and session data
    """

    # Identification
    engagement_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    # Target Information
    target: str = ""
    target_info: TargetInfo = field(default_factory=TargetInfo)

    # Scope and Constraints
    scope: ScopeConfig = field(default_factory=ScopeConfig)

    # Authentication
    auth_token: str | None = None
    auth_cookies: dict[str, str] = field(default_factory=dict)
    auth_headers: dict[str, str] = field(default_factory=dict)
    credentials: dict[str, str] = field(default_factory=dict)

    # Session Data
    session_data: dict[str, Any] = field(default_factory=dict)
    shared_state: dict[str, Any] = field(default_factory=dict)

    # Configuration
    config: dict[str, Any] = field(default_factory=dict)

    # Metadata
    created_at: datetime = field(default_factory=datetime.now)

    def get_auth_headers(self) -> dict[str, str]:
        """Get authentication headers"""
        headers = {}
        headers.update(self.auth_headers)
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        return headers

    def get_cookies(self) -> dict[str, str]:
        """Get all cookies including auth cookies"""
        cookies = {}
        cookies.update(self.auth_cookies)
        return cookies

    def is_in_scope(self, target: str) -> bool:
        """Check if target is within scope"""
        return self.scope.is_in_scope(target)

    def can_perform_destructive(self) -> bool:
        """Check if destructive actions are allowed"""
        return self.scope.allow_destructive

    def get_max_impact(self) -> str:
        """Get maximum allowed impact level"""
        return self.scope.max_impact

    def store_data(self, key: str, value: Any):
        """Store data in session"""
        self.session_data[key] = value

    def get_data(self, key: str, default: Any = None) -> Any:
        """Retrieve data from session"""
        return self.session_data.get(key, default)

    def share_data(self, key: str, value: Any):
        """Share data across attacks"""
        self.shared_state[key] = value

    def get_shared(self, key: str, default: Any = None) -> Any:
        """Get shared data"""
        return self.shared_state.get(key, default)

    def to_dict(self) -> dict[str, Any]:
        """Convert context to dictionary"""
        return {
            "engagement_id": self.engagement_id,
            "session_id": self.session_id,
            "target": self.target,
            "target_info": {
                "url": self.target_info.url,
                "ip": self.target_info.ip,
                "domain": self.target_info.domain,
                "technologies": self.target_info.technologies
            },
            "scope": {
                "allowed_targets": self.scope.allowed_targets,
                "excluded_targets": self.scope.excluded_targets,
                "allow_destructive": self.scope.allow_destructive
            },
            "created_at": self.created_at.isoformat()
        }
