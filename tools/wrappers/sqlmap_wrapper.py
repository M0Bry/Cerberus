"""SQLMap Wrapper — Python interface for sqlmap SQL injection scanner."""

import asyncio
from typing import Any


class SQLMapWrapper:
    """Wrapper for running sqlmap programmatically."""

    async def test_url(self, url: str, param: str | None = None, level: int = 1, risk: int = 1) -> dict[str, Any]:
        """Test a URL for SQL injection."""
        cmd = ["sqlmap", "-u", url, "--level", str(level), "--risk", str(risk), "--batch", "--output-dir=/tmp/sqlmap"]
        if param:
            cmd.extend(["-p", param])
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
            output = stdout.decode()
            vulnerable = "is vulnerable" in output.lower() or "injectable" in output.lower()
            return {"url": url, "vulnerable": vulnerable, "output": output[:5000], "status": "completed"}
        except FileNotFoundError:
            return {"url": url, "error": "sqlmap not installed", "status": "failed"}
        except asyncio.TimeoutError:
            return {"url": url, "error": "Test timed out", "status": "timeout"}
