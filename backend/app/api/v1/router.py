"""
API v1 Router — Aggregates all endpoint routers under /api/v1.
"""

from fastapi import APIRouter

from app.api.v1.endpoints import (
    admin,
    ai_conversation,
    attack_planning,
    auth,
    dashboard,
    defense,
    documents,
    engagements,
    notifications,
    osint,
    red_team,
    reports,
    risk_assessment,
    rules_of_engagement,
    scope,
    users,
)

api_v1_router = APIRouter()

# ─── Authentication & Registration ────────────────────────────
api_v1_router.include_router(
    auth.router,
    prefix="/auth",
    tags=["Authentication"],
)

# ─── User Profile ─────────────────────────────────────────────
api_v1_router.include_router(
    users.router,
    prefix="/users",
    tags=["Users"],
)

# ─── Engagements ──────────────────────────────────────────────
api_v1_router.include_router(
    engagements.router,
    prefix="/engagements",
    tags=["Engagements"],
)

# ─── AI Conversation ──────────────────────────────────────────
api_v1_router.include_router(
    ai_conversation.router,
    prefix="/ai",
    tags=["AI Conversation"],
)

# ─── Scope of Engagement ─────────────────────────────────────
api_v1_router.include_router(
    scope.router,
    prefix="/scope",
    tags=["Scope of Engagement"],
)

# ─── Rules of Engagement ─────────────────────────────────────
api_v1_router.include_router(
    rules_of_engagement.router,
    prefix="/rules",
    tags=["Rules of Engagement"],
)

# ─── Document Upload ──────────────────────────────────────────
api_v1_router.include_router(
    documents.router,
    prefix="/documents",
    tags=["Documents"],
)

# ─── OSINT Phase ──────────────────────────────────────────────
api_v1_router.include_router(
    osint.router,
    prefix="/osint",
    tags=["OSINT"],
)

# ─── Attack Planning ──────────────────────────────────────────
api_v1_router.include_router(
    attack_planning.router,
    prefix="/attack-planning",
    tags=["Attack Planning"],
)

# ─── Red Team Execution ──────────────────────────────────────
api_v1_router.include_router(
    red_team.router,
    prefix="/red-team",
    tags=["Red Team"],
)

# ─── Risk Assessment ──────────────────────────────────────────
api_v1_router.include_router(
    risk_assessment.router,
    prefix="/risk-assessment",
    tags=["Risk Assessment"],
)

# ─── Reports ──────────────────────────────────────────────────
api_v1_router.include_router(
    reports.router,
    prefix="/reports",
    tags=["Reports"],
)

# ─── Dashboard ────────────────────────────────────────────────
api_v1_router.include_router(
    dashboard.router,
    prefix="/dashboard",
    tags=["Dashboard"],
)

# ─── Notifications ────────────────────────────────────────────
api_v1_router.include_router(
    notifications.router,
    prefix="/notifications",
    tags=["Notifications"],
)

# ─── Blue Team Defense ───────────────────────────────────────
api_v1_router.include_router(
    defense.router,
    prefix="/defense",
    tags=["Blue Team Defense"],
)

# ─── Admin ────────────────────────────────────────────────────
api_v1_router.include_router(
    admin.router,
    prefix="/admin",
    tags=["Admin"],
)
