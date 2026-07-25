# Cerberus AI — Intelligent Cybersecurity Platform

> AI-powered penetration testing, automated security assessments, and intelligent cybersecurity analysis.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Environment Variables](#environment-variables)
- [API Documentation](#api-documentation)
- [Scalability Notes](#scalability-notes)
- [License](#license)

---

## Overview

Cerberus AI automates the entire penetration testing lifecycle:

1. **Landing & Registration** — Public-facing marketing page with secure user registration
2. **Email Verification** — OTP-based email verification with hashed codes
3. **Authentication** — Secure login with session management and audit logging
4. **User Dashboard** — Central workspace for managing all engagements
5. **AI Conversation** — Guided AI agent collects engagement requirements via chat
6. **Scope & Rules of Engagement** — Auto-generated legal documents with digital signatures
7. **OSINT Phase** — Automated open-source intelligence gathering
8. **Attack Planning** — AI-driven attack graph construction and path analysis
9. **Red Team Execution** — Controlled proof-of-concept vulnerability validation
10. **Risk Assessment** — Business impact analysis with severity matrices
11. **Report Generation** — Professional PDF reports with remediation roadmaps
12. **Blue Team Defense** — Three-tier security architecture (Gateway → AI Behavioral → Generative AI)

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                     FRONTEND (React)                      │
│  Vite + TypeScript + Tailwind CSS + TanStack Query        │
├──────────────────────────────────────────────────────────┤
│                     REVERSE PROXY (Nginx)                 │
├──────────────────────────────────────────────────────────┤
│                    BACKEND (FastAPI)                       │
│  API Routes → Services → AI Engine → Database             │
├──────────────┬──────────────────────┬────────────────────┤
│  PostgreSQL  │        Redis         │   Celery Workers   │
│  (Primary)   │   (Cache/Session)    │  (Background Jobs) │
└──────────────┴──────────────────────┴────────────────────┘
```

---

## Technology Stack

| Layer       | Technology                                          |
|-------------|-----------------------------------------------------|
| Frontend    | React 18, TypeScript, Vite, Tailwind CSS, TanStack Query |
| Backend     | Python 3.11+, FastAPI, Pydantic v2, SQLAlchemy 2.0  |
| Database    | PostgreSQL 16, Redis 7                              |
| Background  | Celery + Redis Broker                               |
| Auth        | JWT (access + refresh tokens), bcrypt               |
| Email       | SMTP / SendGrid integration                         |
| PDF         | ReportLab / WeasyPrint                              |
| AI/ML       | OpenAI API, LangChain, custom models                |
| DevOps      | Docker, Docker Compose, Nginx                       |
| Testing     | pytest, React Testing Library, Vitest               |

---

## Project Structure

```
cerberus-ai/
├── backend/                    # Python/FastAPI backend
│   ├── app/
│   │   ├── api/                # API route definitions
│   │   │   └── v1/             # API version 1
│   │   │       ├── endpoints/  # Route handlers per feature
│   │   │       └── middleware/ # Request middleware
│   │   ├── core/               # Config, security, exceptions
│   │   ├── db/                 # Database models & repositories
│   │   ├── schemas/            # Pydantic request/response schemas
│   │   ├── services/           # Business logic layer
│   │   ├── ai_engine/          # AI modules (OSINT, Attack, Risk, etc.)
│   │   ├── tasks/              # Celery background tasks
│   │   ├── utils/              # Shared utilities
│   │   └── templates/          # Email & PDF templates
│   ├── tests/                  # Backend tests
│   └── scripts/                # Maintenance scripts
├── frontend/                   # React/TypeScript frontend
│   ├── src/
│   │   ├── components/         # UI components by feature
│   │   ├── pages/              # Route page components
│   │   ├── hooks/              # Custom React hooks
│   │   ├── services/           # API client functions
│   │   ├── store/              # Zustand state management
│   │   ├── slices/             # Feature state slices
│   │   ├── types/              # TypeScript interfaces
│   │   ├── utils/              # Frontend utilities
│   │   └── styles/             # Global styles & Tailwind config
│   └── public/                 # Static assets
├── infrastructure/             # Deployment configs
│   ├── docker/                 # Dockerfiles
│   ├── nginx/                  # Nginx configs
│   └── scripts/                # Deployment scripts
├── docs/                       # Project documentation
└── scripts/                    # Root-level scripts
```

---

## Getting Started

### Prerequisites

- Docker & Docker Compose v2+
- Node.js 18+ (for local frontend dev)
- Python 3.11+ (for local backend dev)

### Quick Start (Docker)

```bash
# Clone and navigate to project
cd cerberus-ai

# Copy environment files
cp backend/.env.example backend/.env
cp frontend/.env.example frontend/.env

# Start all services
docker-compose up -d

# Run database migrations
docker-compose exec backend alembic upgrade head

# Access the platform
# Frontend:  http://localhost:3000
# Backend:   http://localhost:8000
# API Docs:  http://localhost:8000/docs
```

### Local Development

```bash
# Backend
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload

# Frontend
cd frontend
npm install
npm run dev
```

---

## Environment Variables

See `backend/.env.example` and `frontend/.env.example` for full lists.

Key variables:
- `DATABASE_URL` — PostgreSQL connection string
- `REDIS_URL` — Redis connection string
- `SECRET_KEY` — JWT signing secret
- `OPENAI_API_KEY` — OpenAI API key for AI engine
- `SMTP_HOST` / `SMTP_PORT` — Email server configuration

---

## API Documentation

Once running, interactive API docs are available at:
- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`

---

## Scalability Notes

This project is designed for horizontal scaling:

- **Stateless Backend** — All session data in Redis; backend instances can scale independently
- **Modular AI Engine** — Each AI phase (OSINT, Attack, Risk) is an independent module
- **Feature-Based Frontend** — Components organized by feature; new features added as new directories
- **Database Migrations** — Alembic-managed schema changes with version control
- **Background Workers** — Celery workers scale independently for heavy AI processing
- **API Versioning** — All routes under `/api/v1/`; future versions can coexist
- **Plugin Architecture** — New assessment types and AI models can be added without modifying core

---

## License

Proprietary — Cerberus AI © 2026. All rights reserved.
