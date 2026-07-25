"""
AI Services API Gateway — Routes requests to appropriate agents.
"""

import structlog
from fastapi import FastAPI, Request

logger = structlog.get_logger()

app = FastAPI(title="Cerberus AI Services Gateway", version="1.0.0")

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "ai-gateway"}

@app.post("/agents/{agent_name}/execute")
async def execute_agent(agent_name: str, request: Request):
    """Route request to a specific agent."""
    data = await request.json()
    logger.info("agent_execution", agent=agent_name)
    return {"agent": agent_name, "status": "queued", "data": data}
