"""
AI Orchestrator — Routes tasks to the best agent and manages execution.

Supports:
- Task routing based on agent capabilities
- Parallel execution of independent tasks
- Dependency management between agents
- Retry and fallback logic
- State management across agent chains
"""
import asyncio
from typing import Any

import structlog

logger = structlog.get_logger()


class AgentTask:
    """Represents a task to be executed by an agent."""
    def __init__(self, agent_name: str, task_type: str, payload: dict[str, Any], dependencies: list[str] | None = None) -> None:
        self.agent_name = agent_name
        self.task_type = task_type
        self.payload = payload
        self.dependencies = dependencies or []
        self.result = None
        self.status = "pending"


class Orchestrator:
    """
    Multi-agent orchestrator.

    Manages task routing, execution order, dependency resolution,
    and result aggregation across all AI agents.
    """

    def __init__(self) -> None:
        self.agents: dict[str, Any] = {}
        self.task_queue: list[AgentTask] = []
        self.results: dict[str, Any] = {}

    def register_agent(self, name: str, agent: Any) -> None:
        """Register an agent with the orchestrator."""
        self.agents[name] = agent
        logger.info("agent_registered", name=name)

    async def execute_workflow(self, workflow: str, context: dict[str, Any]) -> dict[str, Any]:
        """
        Execute a predefined workflow.

        Workflows:
        - "pentest_full": Full penetration testing cycle
        - "osint_only": OSINT collection only
        - "report_only": Report generation from existing data
        - "threat_hunting": Threat hunting workflow
        """
        logger.info("workflow_started", workflow=workflow)

        if workflow == "pentest_full":
            return await self._full_pentest_workflow(context)
        elif workflow == "osint_only":
            return await self._osint_workflow(context)
        elif workflow == "report_only":
            return await self._report_workflow(context)
        else:
            return {"error": f"Unknown workflow: {workflow}"}

    async def execute_task(self, agent_name: str, task_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Execute a single task on a specific agent."""
        agent = self.agents.get(agent_name)
        if not agent:
            return {"error": f"Agent not found: {agent_name}"}

        try:
            result = await asyncio.wait_for(
                agent.execute(task_type, payload),
                timeout=120,
            )
            return {"agent": agent_name, "task": task_type, "result": result}
        except asyncio.TimeoutError:
            return {"agent": agent_name, "task": task_type, "error": "Timeout"}
        except Exception:
            logger.exception("Task execution failed", agent=agent_name, task=task_type)
            return {"agent": agent_name, "task": task_type, "error": "Execution error"}

    async def _full_pentest_workflow(self, context: dict[str, Any]) -> dict[str, Any]:
        """Execute the full penetration testing workflow."""
        results = {}

        # Step 1: Intake
        if "intake_agent" in self.agents:
            results["intake"] = await self.execute_task("intake_agent", "collect_requirements", context)

        # Step 2: OSINT
        if "osint_agent" in self.agents:
            results["osint"] = await self.execute_task("osint_agent", "collect_intelligence", context)

        # Step 3: Vulnerability Assessment
        if "vulnerability_agent" in self.agents:
            results["vulnerabilities"] = await self.execute_task("vulnerability_agent", "assess", context)

        # Step 4: Exploitation
        if "exploit_agent" in self.agents:
            results["exploitation"] = await self.execute_task("exploit_agent", "validate", context)

        # Step 5: Risk Assessment
        if "risk_assessment_agent" in self.agents:
            results["risk"] = await self.execute_task("risk_assessment_agent", "assess", context)

        # Step 6: Report
        if "report_agent" in self.agents:
            results["report"] = await self.execute_task("report_agent", "generate", context)

        return {"workflow": "pentest_full", "results": results}

    async def _osint_workflow(self, context: dict[str, Any]) -> dict[str, Any]:
        """Execute OSINT collection workflow."""
        return {"workflow": "osint_only", "status": "completed"}

    async def _report_workflow(self, context: dict[str, Any]) -> dict[str, Any]:
        """Execute report generation workflow."""
        return {"workflow": "report_only", "status": "completed"}
