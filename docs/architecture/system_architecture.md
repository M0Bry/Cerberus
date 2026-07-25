# System Architecture

## Overview
Cerberus AI follows a modular monolith architecture with clear separation of concerns.

## Layers
1. **Frontend** (React + TypeScript + Vite) — SPA with TanStack Query
2. **Reverse Proxy** (Nginx) — SSL termination, rate limiting, caching
3. **Backend** (FastAPI + Python) — RESTful API with async support
4. **Database** (PostgreSQL) — Primary data store
5. **Cache/Queue** (Redis) — Sessions, OTP, rate limiting, Celery broker
6. **Background Workers** (Celery) — AI tasks, email, monitoring
7. **AI Engine** — Multi-model orchestration with sandboxed execution

## Design Principles
- Security-by-Design
- Modular architecture
- Stateless backend for horizontal scaling
- Immutable audit logs
- Three-tier defense architecture
