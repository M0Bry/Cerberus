"""Health checks for AI services."""
from fastapi import APIRouter

router = APIRouter()

@router.get("/health")
async def health():
    return {"status": "healthy"}

@router.get("/health/detailed")
async def detailed_health():
    return {"gateway": "ok", "orchestrator": "ok", "agents": "ok", "memory": "ok", "llm": "ok"}
