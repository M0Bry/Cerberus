"""
Base class for network attacks.
"""

import asyncio

import structlog

logger = structlog.get_logger()


class BaseNetworkAttack:
    """Common network attack operations."""

    async def test_connectivity(self, host: str, port: int, timeout: float = 3.0) -> bool:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            writer.close()
            return True
        except Exception:  # noqa: BLE001
            return False

    async def send_payload(self, host: str, port: int, data: bytes, timeout: float = 5.0) -> str | None:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            writer.write(data)
            writer.close()
            return data.decode(errors="ignore").strip()
        except Exception:  # noqa: BLE001
            return None
