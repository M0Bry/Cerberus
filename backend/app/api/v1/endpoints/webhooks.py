"""Webhooks: external integrations.

NOTE: the Stripe webhook lives at POST /api/v1/payments/webhook
(app/api/v1/endpoints/payments.py) and is signature-verified. Do not
re-add an unverified stripe endpoint here.
"""

from fastapi import APIRouter, Request

router = APIRouter()


@router.post("/slack")
async def slack_webhook(request: Request):
    return {"received": True}
