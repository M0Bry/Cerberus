"""Cerberus AI Agent — Standalone AI microservice."""

from fastapi import FastAPI

app = FastAPI(title="Cerberus AI Agent")


@app.get("/health")
async def health() -> dict:
    """Return service health status."""
    return {"status": "healthy"}


@app.post("/analyze")
async def analyze(data: dict) -> dict:
    """Analyze input data and return a placeholder result."""
    return {"result": "placeholder"}
