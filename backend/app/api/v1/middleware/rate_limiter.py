"""
Rate Limiter Middleware — Prevents abuse using Redis-backed rate limiting.
"""

import time

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import ORJSONResponse, Response

from app.core.config import settings


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Simple rate limiter using request counting.

    In production, use Redis-backed sliding window for distributed rate limiting.
    """

    def __init__(self, app):
        super().__init__(app)
        self.requests: dict[str, list[float]] = {}

    async def dispatch(self, request: Request, call_next) -> Response:
        # Skip rate limiting for health checks
        if request.url.path in ("/health", "/docs", "/openapi.json"):
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        current_time = time.time()

        # Determine rate limit based on path
        if "/auth/login" in str(request.url.path):
            max_requests = settings.RATE_LIMIT_LOGIN_PER_MINUTE
        else:
            max_requests = settings.RATE_LIMIT_PER_MINUTE

        # Clean old entries
        if client_ip in self.requests:
            self.requests[client_ip] = [
                t for t in self.requests[client_ip] if current_time - t < 60
            ]
        else:
            self.requests[client_ip] = []

        # Check rate limit
        if len(self.requests[client_ip]) >= max_requests:
            return ORJSONResponse(
                status_code=429,
                content={
                    "success": False,
                    "error": {
                        "code": 429,
                        "message": "Rate limit exceeded. Please try again later.",
                    },
                },
            )

        # Record request
        self.requests[client_ip].append(current_time)

        response = await call_next(request)
        return response
