"""Webhooks: external integrations (Stripe, Slack, etc.)."""

from fastapi import APIRouter, Request

router = APIRouter()


@router.post("/stripe")
async def stripe_webhook(request: Request):
    return {"received": True}


@router.post("/slack")
async def slack_webhook(request: Request):
    return {"received": True}
