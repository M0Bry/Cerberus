"""
Permissions — RBAC (Role-Based Access Control) + Permission Matrix.
"""

import enum
from functools import wraps

from app.core.exceptions import AuthorizationError


class Permission(str, enum.Enum):  # noqa: UP042
    """All granular permissions in the system."""

    # User
    USER_READ = "user:read"
    USER_UPDATE = "user:update"
    USER_DELETE = "user:delete"
    USER_MANAGE = "user:manage"

    # Engagement
    ENGAGEMENT_CREATE = "engagement:create"
    ENGAGEMENT_READ = "engagement:read"
    ENGAGEMENT_UPDATE = "engagement:update"
    ENGAGEMENT_DELETE = "engagement:delete"

    # Scope
    SCOPE_CREATE = "scope:create"
    SCOPE_READ = "scope:read"
    SCOPE_CONFIRM = "scope:confirm"

    # OSINT
    OSINT_START = "osint:start"
    OSINT_READ = "osint:read"

    # Red Team
    REDTEAM_START = "redteam:start"
    REDTEAM_READ = "redteam:read"

    # Risk
    RISK_READ = "risk:read"
    RISK_CONFIRM = "risk:confirm"

    # Reports
    REPORT_GENERATE = "report:generate"
    REPORT_READ = "report:read"
    REPORT_DOWNLOAD = "report:download"

    # Admin
    ADMIN_DASHBOARD = "admin:dashboard"
    ADMIN_USERS = "admin:users"
    ADMIN_SYSTEM = "admin:system"
    ADMIN_AUDIT = "admin:audit"

    # Monitoring
    MONITORING_READ = "monitoring:read"
    MONITORING_MANAGE = "monitoring:manage"

    # AI
    AI_CHAT = "ai:chat"
    AI_CONFIGURE = "ai:configure"


class Role(str, enum.Enum):  # noqa: UP042
    SUPER_ADMIN = "super_admin"
    ADMIN = "admin"
    PENTESTER = "pentester"
    CLIENT = "client"
    VIEWER = "viewer"


# ─── Role → Permission Mapping ────────────────────────────────
ROLE_PERMISSIONS: dict[Role, set[Permission]] = {
    Role.SUPER_ADMIN: set(Permission),  # All permissions
    Role.ADMIN: {
        Permission.USER_READ, Permission.USER_MANAGE,
        Permission.ENGAGEMENT_READ, Permission.ENGAGEMENT_CREATE,
        Permission.SCOPE_READ, Permission.SCOPE_CREATE, Permission.SCOPE_CONFIRM,
        Permission.OSINT_READ, Permission.REDTEAM_READ,
        Permission.RISK_READ, Permission.RISK_CONFIRM,
        Permission.REPORT_READ, Permission.REPORT_GENERATE, Permission.REPORT_DOWNLOAD,
        Permission.ADMIN_DASHBOARD, Permission.ADMIN_USERS, Permission.ADMIN_AUDIT,
        Permission.MONITORING_READ, Permission.MONITORING_MANAGE,
        Permission.AI_CHAT,
    },
    Role.PENTESTER: {
        Permission.USER_READ,
        Permission.ENGAGEMENT_READ,
        Permission.SCOPE_READ,
        Permission.OSINT_START, Permission.OSINT_READ,
        Permission.REDTEAM_START, Permission.REDTEAM_READ,
        Permission.RISK_READ,
        Permission.REPORT_READ, Permission.REPORT_GENERATE, Permission.REPORT_DOWNLOAD,
        Permission.AI_CHAT,
    },
    Role.CLIENT: {
        Permission.ENGAGEMENT_CREATE, Permission.ENGAGEMENT_READ,
        Permission.SCOPE_READ, Permission.SCOPE_CONFIRM,
        Permission.OSINT_READ,
        Permission.REDTEAM_READ,
        Permission.RISK_READ, Permission.RISK_CONFIRM,
        Permission.REPORT_READ, Permission.REPORT_DOWNLOAD,
        Permission.AI_CHAT,
    },
    Role.VIEWER: {
        Permission.ENGAGEMENT_READ,
        Permission.SCOPE_READ,
        Permission.OSINT_READ,
        Permission.REDTEAM_READ,
        Permission.RISK_READ,
        Permission.REPORT_READ,
    },
}


def get_permissions_for_role(role: Role) -> set[Permission]:
    return ROLE_PERMISSIONS.get(role, set())


def check_permission(user_role: Role, required: Permission) -> None:
    if required not in get_permissions_for_role(user_role):
        raise AuthorizationError(
            f"Permission '{required.value}' required. "
            f"Your role '{user_role.value}' lacks this permission."
        )


def require_permission(permission: Permission):
    """Decorator for service methods requiring a specific permission."""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            user = kwargs.get("user") or (args[1] if len(args) > 1 else None)
            if user and hasattr(user, "role"):
                check_permission(Role(user.role), permission)
            return await func(*args, **kwargs)
        return wrapper
    return decorator
