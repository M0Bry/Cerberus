"""Public endpoints (landing stats, health, contact)."""

from fastapi import APIRouter

router = APIRouter()


@router.get("/stats")
async def get_landing_stats():
    return {
        "assessments": 1247,
        "organizations": 389,
        "vulnerabilities": 15632,
        "reports": 892,
    }


@router.post("/contact")
async def contact_form(data: dict):
    return {"success": True, "message": "Thank you for contacting us."}
