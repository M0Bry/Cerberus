"""
Custom Exception Classes and Global Exception Handlers.

Provides consistent error responses across the entire API.
"""

from fastapi import FastAPI, Request, status
from fastapi.responses import ORJSONResponse


# ─── Custom Exception Classes ────────────────────────────────
class CerberusError(Exception):
    """Base exception for all Cerberus-specific errors."""

    def __init__(self, detail: str = "An error occurred", status_code: int = 500):
        self.detail = detail
        self.status_code = status_code
        super().__init__(detail)


class AuthenticationError(CerberusError):
    """Raised when authentication fails."""

    def __init__(self, detail: str = "Invalid credentials"):
        super().__init__(detail=detail, status_code=401)


class AuthorizationError(CerberusError):
    """Raised when user lacks required permissions."""

    def __init__(self, detail: str = "Insufficient permissions"):
        super().__init__(detail=detail, status_code=403)


class NotFoundError(CerberusError):
    """Raised when a requested resource is not found."""

    def __init__(self, detail: str = "Resource not found"):
        super().__init__(detail=detail, status_code=404)


class ValidationError(CerberusError):
    """Raised when input validation fails."""

    def __init__(self, detail: str = "Validation error"):
        super().__init__(detail=detail, status_code=422)


class ConflictError(CerberusError):
    """Raised when a resource conflict occurs (e.g., duplicate email)."""

    def __init__(self, detail: str = "Resource conflict"):
        super().__init__(detail=detail, status_code=409)


class OTPError(CerberusError):
    """Raised when OTP verification fails."""

    def __init__(self, detail: str = "Invalid or expired verification code"):
        super().__init__(detail=detail, status_code=400)


class RateLimitError(CerberusError):
    """Raised when rate limit is exceeded."""

    def __init__(self, detail: str = "Rate limit exceeded. Please try again later."):
        super().__init__(detail=detail, status_code=429)


class FileUploadError(CerberusError):
    """Raised when file upload validation fails."""

    def __init__(self, detail: str = "File upload rejected"):
        super().__init__(detail=detail, status_code=400)


class EngagementError(CerberusError):
    """Raised when an engagement operation fails."""

    def __init__(self, detail: str = "Engagement operation failed"):
        super().__init__(detail=detail, status_code=400)


class AIEngineError(CerberusError):
    """Raised when an AI engine operation fails."""

    def __init__(self, detail: str = "AI processing error"):
        super().__init__(detail=detail, status_code=500)


# ─── Global Exception Handlers ───────────────────────────────
def register_exception_handlers(app: FastAPI) -> None:
    """Register all global exception handlers on the FastAPI application."""

    @app.exception_handler(CerberusError)
    async def cerberus_exception_handler(request: Request, exc: CerberusError):
        return ORJSONResponse(
            status_code=exc.status_code,
            content={
                "success": False,
                "error": {
                    "code": exc.status_code,
                    "message": exc.detail,
                },
            },
        )

    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        return ORJSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "success": False,
                "error": {
                    "code": 500,
                    "message": "Internal server error",
                },
            },
        )
