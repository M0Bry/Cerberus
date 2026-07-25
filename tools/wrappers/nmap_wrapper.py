"""Nmap Wrapper — Python interface for nmap network scanner."""

import asyncio
from typing import Any


class NmapWrapper:
    """Wrapper for running nmap scans programmatically."""

    async def quick_scan(self, target: str, ports: str = "1-1000") -> dict[str, Any]:
        """Run a quick TCP SYN scan."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "nmap", target, "-p", ports, "-sS", "-oX", "-",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
            return {"target": target, "raw_xml": stdout.decode(), "status": "completed"}
        except FileNotFoundError:
            return {"target": target, "error": "nmap not found", "status": "failed"}
        except asyncio.TimeoutError:
            return {"target": target, "error": "Scan timed out", "status": "timeout"}

    async def service_scan(self, target: str, ports: str) -> dict[str, Any]:
        """Run service version detection."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "nmap", target, "-p", ports, "-sV", "-oX", "-",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=600)
            return {"target": target, "raw_xml": stdout.decode(), "status": "completed"}
        except Exception as e:  # noqa: BLE001
            return {"target": target, "error": str(e), "status": "failed"}

    async def vulnerability_scan(self, target: str, ports: str) -> dict[str, Any]:
        """Run nmap vulnerability scripts."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "nmap", target, "-p", ports, "-sV", "--script=vuln", "-oX", "-",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=900)
            return {"target": target, "raw_xml": stdout.decode(), "status": "completed"}
        except Exception as e:  # noqa: BLE001
            return {"target": target, "error": str(e), "status": "failed"}
