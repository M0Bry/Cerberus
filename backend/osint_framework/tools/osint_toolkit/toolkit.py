"""
OSINT Toolkit — Unified Interface for Multiple OSINT Tools.

Provides a single entry point to run investigations using
Sherlock Pro, Photon X, and other integrated tools.
"""

import json
from datetime import datetime, timezone
from typing import Any

import structlog

from osint_framework.tools.photon_x.photon_x import PhotonX
from osint_framework.tools.sherlock_pro.sherlock_pro import SherlockPro

logger = structlog.get_logger(__name__)


class OSINTToolkit:
    """
    Unified interface for OSINT investigations.

    Usage:
        toolkit = OSINTToolkit()
        report = await toolkit.run_investigation("example.com")
        toolkit.export_investigation(report, "report.json")
    """

    def __init__(self) -> None:
        self.results: dict[str, Any] = {}
        self.tools = {
            "sherlock_pro": SherlockPro,
            "photon_x": PhotonX,
        }

    async def run_investigation(
        self, target: str, tools: list[str] | None = None
    ) -> dict[str, Any]:
        """
        Run a complete investigation using specified tools.

        Args:
            target: Target to investigate (domain, username, email, etc.)
            tools: List of tool names to use (None = auto-select).

        Returns:
            Comprehensive investigation report.
        """
        target_type = self._classify_target(target)
        logger.info("investigation_started", target=target, type=target_type)

        # Build the investigation dict with explicit types for mutable fields
        tools_used: list[str] = []
        findings: dict[str, Any] = {}

        investigation: dict[str, Any] = {
            "investigation_id": (
                "INV-"
                + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")  # noqa: UP017
            ),
            "target": target,
            "target_type": target_type,
            "start_time": datetime.now(timezone.utc).isoformat(),  # noqa: UP017
            "tools_used": tools_used,
            "findings": findings,
            "summary": {},
        }

        # Auto-select tools based on target type
        if tools is None:
            tools = self._select_tools(target_type)

        # Run tools concurrently
        for tool_name in tools:
            try:
                result = await self._run_tool(tool_name, target)
                findings[tool_name] = result
                tools_used.append(tool_name)
            except Exception as e:
                logger.error("tool_error", tool=tool_name, error=str(e))
                findings[tool_name] = {"error": str(e)}

        investigation["summary"] = self._generate_summary(findings)
        investigation["end_time"] = datetime.now(timezone.utc).isoformat()  # noqa: UP017

        self.results = investigation
        return investigation

    async def run_tool(self, tool_name: str, target: str) -> dict[str, Any]:
        """Run a specific tool against a target."""
        return await self._run_tool(tool_name, target)

    async def _run_tool(self, tool_name: str, target: str) -> dict[str, Any]:
        """Execute a specific tool."""
        now = datetime.now(timezone.utc).isoformat()  # noqa: UP017
        if tool_name == "sherlock_pro":
            async with SherlockPro() as sherlock:
                results = await sherlock.search_username(target)
                return {
                    "tool": tool_name,
                    "target": target,
                    "results": [
                        {
                            "platform": r.platform,
                            "url": r.url,
                            "exists": r.exists,
                        }
                        for r in results
                    ],
                    "profiles_found": sum(1 for r in results if r.exists),
                    "timestamp": now,
                }
        elif tool_name == "photon_x":
            crawler = PhotonX()
            results = await crawler.crawl(target)
            return {
                "tool": tool_name,
                "target": target,
                "results": results,
                "timestamp": now,
            }
        else:
            return {"error": f"Unknown tool: {tool_name}"}

    def export_investigation(
        self,
        investigation: dict[str, Any] | None = None,
        filename: str | None = None,
    ) -> str:
        """Export investigation results to file."""
        data = investigation or self.results
        if not filename:
            filename = (
                f"investigation_{data.get('investigation_id', 'unknown')}.json"
            )

        with open(filename, "w") as f:
            json.dump(data, f, indent=2, default=str)

        logger.info("investigation_exported", filename=filename)
        return filename

    @staticmethod
    def _classify_target(target: str) -> str:
        """Classify the target type."""
        if "@" in target:
            return "email"
        elif target.startswith("http://") or target.startswith("https://"):
            return "url"
        elif "." in target and " " not in target:
            return "domain"
        else:
            return "username"

    @staticmethod
    def _select_tools(target_type: str) -> list[str]:
        """Select appropriate tools based on target type."""
        mapping = {
            "username": ["sherlock_pro"],
            "domain": ["photon_x"],
            "url": ["photon_x"],
            "email": ["sherlock_pro", "photon_x"],
        }
        return mapping.get(target_type, ["sherlock_pro"])

    @staticmethod
    def _generate_summary(findings: dict[str, Any]) -> dict[str, int]:
        """Generate a summary of all findings."""
        summary = {
            "total_tools_used": len(findings),
            "total_findings": 0,
            "high_severity": 0,
            "medium_severity": 0,
            "low_severity": 0,
        }

        for result in findings.values():
            if not isinstance(result, dict):
                continue
            if "error" in result:
                continue
            if "profiles_found" in result:
                summary["total_findings"] += result.get("profiles_found", 0)
            else:
                sec = result.get("results", {}).get("security_findings", {})
                if isinstance(sec, dict):
                    summary["high_severity"] += sec.get("secrets_found", 0)
                emails = (
                    result.get("results", {})
                    .get("intelligence", {})
                    .get("emails", [])
                )
                summary["total_findings"] += len(emails)

        return summary
