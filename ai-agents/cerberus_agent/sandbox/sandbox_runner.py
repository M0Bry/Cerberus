"""Sandbox runner for isolated tool execution."""
class SandboxRunner:
    async def run(self, image: str, command: str) -> dict: return {"exit_code": 0, "stdout": ""}
