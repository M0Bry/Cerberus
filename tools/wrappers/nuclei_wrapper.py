"""Nuclei Wrapper — Python interface for nuclei vulnerability scanner."""

import asyncio
import json
from typing import Any


class NucleiWrapper:
    """Wrapper for running nuclei scans programmatically."""

    async def scan(self, target: str, templates: str = "", severity: str = "critical,high,medium") -> dict[str, Any]:
        """Run nuclei scan against a target."""
        cmd = ["nuclei", "-u", target, "-severity", severity, "-jsonl", "-silent"]
        if templates:
            cmd.extend(["-t", templates])
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=600)
            findings = []
            for line in stdout.decode().strip().split("\n"):
                if line:
                    try:
                        findings.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
            return {"target": target, "findings": findings, "status": "completed"}
        except FileNotFoundError:
            return {"target": target, "error": "nuclei not installed", "status": "failed"}
        except asyncio.TimeoutError:
            return {"target": target, "error": "Scan timed out", "status": "timeout"}
