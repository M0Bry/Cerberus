"""
Admin Schemas — Request/Response models for admin endpoints.
"""

from datetime import datetime

from pydantic import BaseModel


class AdminDashboardResponse(BaseModel):
    success: bool = True
    total_users: int
    active_users: int
    total_engagements: int
    active_engagements: int
    total_reports: int
    system_health: str


class AdminUserItem(BaseModel):
    id: str
    full_name: str
    email: str
    company_name: str
    role: str
    status: str
    created_at: datetime
    last_login_at: datetime | None


class UserManagementListResponse(BaseModel):
    success: bool = True
    total: int
    page: int
    page_size: int
    items: list[AdminUserItem]


class AuditLogItem(BaseModel):
    id: str
    action: str
    severity: str
    description: str
    user_id: str | None
    ip_address: str | None
    created_at: datetime

    class Config:
        from_attributes = True


class SystemAuditLogResponse(BaseModel):
    success: bool = True
    total: int
    page: int
    page_size: int
    items: list[AuditLogItem]
