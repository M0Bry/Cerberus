"""Access Endpoints — the logged-in user's trial / paid / suspended state."""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.access import AccessInfo
from app.services.access_service import AccessService

router = APIRouter()


@router.get("", response_model=AccessInfo)
async def get_my_access(
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> AccessInfo:
    """Effective access state of the current account.

    A suspended trial is recorded in the database on first observation
    (the suspension is a DB fact, per product rule).
    """
    service = AccessService(db)
    return await service.get_access(current_user)
