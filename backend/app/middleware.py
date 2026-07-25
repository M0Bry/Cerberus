"""
Middleware — CORS, trusted hosts, logging, rate limit, IP log.
"""

import time
import uuid

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = structlog.get_logger()


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Logs every request with timing, status, client IP, and correlation ID."""

    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        start = time.time()

        client_ip = request.client.host if request.client else "unknown"

        response = await call_next(request)
        duration_ms = round((time.time() - start) * 1000, 2)

        logger.info(
            "request",
            request_id=request_id,
            method=request.method,
            path=str(request.url.path),
            status=response.status_code,
            duration_ms=duration_ms,
            client_ip=client_ip,
        )

        response.headers["X-Request-ID"] = request_id
        return response
