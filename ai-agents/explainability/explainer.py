"""Explainability service for AI decisions."""

from fastapi import FastAPI

app = FastAPI(title="Cerberus Explainability")


@app.get("/health")
async def health() -> dict:
    """Return service health status."""
    return {"status": "healthy"}


@app.post("/explain")
async def explain(data: dict) -> dict:
    """Return a placeholder explanation for the given data."""
    return {"explanation": "placeholder"}
