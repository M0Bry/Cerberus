"""
Rate Limiter Middleware — Prevents abuse using Redis-backed rate limiting.
"""

import time

from fastapi import Request
from fastapi.responses import ORJSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from app.core.config import settings


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Simple rate limiter using request counting.

    In production, use Redis-backed sliding window for distributed rate limiting.
    """

    def __init__(self, app):
        super().__init__(app)
        self.requests: dict[str, list[float]] = {}
        RateLimitMiddleware.instances.append(self)

    @classmethod
    def reset_all(cls) -> None:
        """Clear every limiter bucket (used by the test-suite isolation
        fixture; safe to call at runtime during ops if needed)."""
        for instance in cls.instances:
            instance.requests.clear()

    instances: list["RateLimitMiddleware"] = []

    async def dispatch(self, request: Request, call_next) -> Response:
        # Skip rate limiting for health checks
        if request.url.path in ("/health", "/docs", "/openapi.json"):
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        current_time = time.time()

        # Determine rate limit based on path. Buckets are kept SEPARATE per
        # surface: the login bucket must not be poisoned by ordinary page
        # traffic from the same IP (a user who browsed a few pages within
        # the last minute must still be able to log in).
        if "/auth/login" in str(request.url.path):
            max_requests = settings.RATE_LIMIT_LOGIN_PER_MINUTE
            bucket_key = f"{client_ip}:login"
        else:
            max_requests = settings.RATE_LIMIT_PER_MINUTE
            bucket_key = f"{client_ip}:general"

        # Clean old entries
        if bucket_key in self.requests:
            self.requests[bucket_key] = [
                t for t in self.requests[bucket_key] if current_time - t < 60
            ]
        else:
            self.requests[bucket_key] = []

        # Check rate limit
        if len(self.requests[bucket_key]) >= max_requests:
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
        self.requests[bucket_key].append(current_time)

        response = await call_next(request)
        return response
