FROM mcr.microsoft.com/devcontainers/python:3.13

# Install Node.js and system dependencies
RUN apt-get update && apt-get install -y \
    nodejs \
    npm \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dev tools
RUN pip install ruff black mypy pytest pytest-asyncio

WORKDIR /workspace
