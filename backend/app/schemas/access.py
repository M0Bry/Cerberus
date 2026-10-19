"""Access Schemas — trial / paid / suspended access state for the logged-in user."""

from datetime import datetime

from pydantic import BaseModel


class AccessInfo(BaseModel):
    """Effective access state of an account.

    state:
      "paid"      — an active subscription (ACTIVE / TRIALING / PAST_DUE)
      "trial"     — within the 7-day free trial, full access
      "suspended" — trial expired with no subscription; recorded as
                    SUSPENDED in the database until payment. Login is still
                    allowed (the user must reach Billing to pay) but new
                    assessments are blocked.
    """

    state: str
    plan_name: str | None = None
    subscription_status: str | None = None
    trial_ends_at: datetime
    trial_days_left: int
    is_admin: bool = False
