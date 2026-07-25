"""Docker Sandbox Runner — Isolated tool execution in containers."""

import structlog

logger = structlog.get_logger()


class DockerSandboxRunner:
    """Runs security tools in isolated Docker containers."""

    def __init__(self):
        self.containers = []

    async def run_tool(
        self,
        image: str,
        command: str,
        timeout: int = 300,
        network: str = "none",
    ) -> dict:
        """Run a tool in a sandboxed Docker container."""
        logger.info("sandbox_run", image=image, command=command[:100])
        # In production:
        # docker.containers.run(image, command, network_mode=network, mem_limit="512m")
        return {"exit_code": 0, "stdout": "", "stderr": "", "duration_ms": 0}

    async def cleanup(self):
        """Remove all sandbox containers."""
        logger.info("sandbox_cleanup", containers=len(self.containers))
        self.containers.clear()
