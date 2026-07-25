"""
Request Logging Middleware — Logs all incoming requests for security auditing.
"""

import time
import uuid

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = structlog.get_logger()


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Logs every request with timing, status, and correlation ID."""

    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = str(uuid.uuid4())
        start_time = time.time()

        # Attach request ID to request state
        request.state.request_id = request_id

        # Extract client info
        client_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("user-agent", "unknown")

        response = await call_next(request)

        # Calculate duration
        duration_ms = round((time.time() - start_time) * 1000, 2)

        # Log the request
        logger.info(
            "request_completed",
            request_id=request_id,
            method=request.method,
            path=str(request.url.path),
            status_code=response.status_code,
            duration_ms=duration_ms,
            client_ip=client_ip,
            user_agent=user_agent[:200] if user_agent else None,
        )

        # Add request ID to response headers
        response.headers["X-Request-ID"] = request_id
        return response
