"""
Exceptions — Custom exception classes + global exception handlers.
"""

from fastapi import FastAPI, Request
from fastapi.responses import ORJSONResponse


class CerberusError(Exception):
    def __init__(self, detail: str = "An error occurred", status_code: int = 500):
        self.detail = detail
        self.status_code = status_code


class AuthenticationError(CerberusError):
    def __init__(self, detail: str = "Invalid credentials"):
        super().__init__(detail, 401)


class AuthorizationError(CerberusError):
    def __init__(self, detail: str = "Insufficient permissions"):
        super().__init__(detail, 403)


class NotFoundError(CerberusError):
    def __init__(self, detail: str = "Not found"):
        super().__init__(detail, 404)


class ValidationError(CerberusError):
    def __init__(self, detail: str = "Validation error"):
        super().__init__(detail, 422)


class ConflictError(CerberusError):
    def __init__(self, detail: str = "Conflict"):
        super().__init__(detail, 409)


class RateLimitError(CerberusError):
    def __init__(self, detail: str = "Rate limit exceeded"):
        super().__init__(detail, 429)


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(CerberusError)
    async def cerberus_handler(request: Request, exc: CerberusError):
        return ORJSONResponse(
            status_code=exc.status_code,
            content={
                "success": False,
                "error": {"code": exc.status_code, "message": exc.detail},
            },
        )

    @app.exception_handler(Exception)
    async def global_handler(request: Request, exc: Exception):
        return ORJSONResponse(
            status_code=500,
            content={
                "success": False,
                "error": {"code": 500, "message": "Internal server error"},
            },
        )
