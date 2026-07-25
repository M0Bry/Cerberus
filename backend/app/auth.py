"""OAuth2 + Bearer token flow, refresh token rotation."""

from app.api.deps import get_current_user
from app.core.security import create_access_token, create_refresh_token, decode_token

# This module serves as a placeholder for future OAuth2 implementation.
# Imports are currently unused and will be activated when routes are added.
__all__ = [
    "create_access_token",
    "create_refresh_token",
    "decode_token",
    "get_current_user",
]
