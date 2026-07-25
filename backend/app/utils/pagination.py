"""Pagination Helpers — Standardized pagination for DB queries."""

from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession


class PaginatedResponse(BaseModel):
    total: int
    page: int
    page_size: int
    total_pages: int
    items: list


def paginate_query(query, page: int = 1, page_size: int = 20):
    """Apply pagination to a SQLAlchemy query."""
    offset = (page - 1) * page_size
    return query.offset(offset).limit(page_size)


async def get_paginated(
    db: AsyncSession,
    query,
    page: int = 1,
    page_size: int = 20,
) -> PaginatedResponse:
    """Execute a paginated query and return standardized response."""
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0

    paged = paginate_query(query, page, page_size)
    result = await db.execute(paged)
    items = result.scalars().all()

    return PaginatedResponse(
        total=total,
        page=page,
        page_size=page_size,
        total_pages=max(1, (total + page_size - 1) // page_size),
        items=[item.__dict__ if hasattr(item, "__dict__") else item for item in items],
    )
