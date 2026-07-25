# Cerberus AI — Architecture Documentation

## System Overview

Cerberus AI is built as a **modular, layered monolith** designed for horizontal scaling. The architecture follows a strict separation of concerns with clearly defined interfaces between layers.

```
┌─────────────────────────────────────────────────────────────┐
│                    CLIENT LAYER (Browser)                     │
│  React SPA + TypeScript + Tailwind CSS + TanStack Query      │
├─────────────────────────────────────────────────────────────┤
│                   PROXY LAYER (Nginx)                         │
│  SSL Termination · Rate Limiting · Static Asset Serving       │
├─────────────────────────────────────────────────────────────┤
│                   API LAYER (FastAPI)                         │
│  Routes → Dependencies → Middleware → Exception Handlers      │
├─────────────────────────────────────────────────────────────┤
│                 SERVICE LAYER (Business Logic)                │
│  AuthService · EngagementService · OSINTService · etc.        │
├─────────────────────────────────────────────────────────────┤
│                  AI ENGINE LAYER                              │
│  Conversation · OSINT Collector · Attack Graph · Risk Analyzer│
│  Report Builder · Three-Tier Defense Engine                   │
├─────────────────────────────────────────────────────────────┤
│               DATA LAYER (Models + Repositories)              │
│  SQLAlchemy Async · Alembic Migrations · Redis Cache          │
├──────────────┬────────────────────┬─────────────────────────┤
│  PostgreSQL  │       Redis        │    Celery Workers        │
│  (Primary)   │  (Cache/Session)   │   (Background Jobs)      │
└──────────────┴────────────────────┴─────────────────────────┘
```

## Layer Descriptions

### 1. API Layer (`app/api/`)
- **Router**: Aggregates all endpoint modules under `/api/v1`
- **Endpoints**: Feature-specific route handlers (auth, engagements, osint, etc.)
- **Middleware**: Request logging, rate limiting, CORS
- **Dependencies**: Shared auth extraction, DB session injection
- **Scalability**: New features = new endpoint file + add to router

### 2. Service Layer (`app/services/`)
- Contains all business logic
- Services are injected with a DB session
- Each service handles one domain (auth, engagement, osint, etc.)
- **Scalability**: New business logic = new service file

### 3. AI Engine Layer (`app/ai_engine/`)
- Independent AI modules for each assessment phase
- Modules: Conversation, OSINT Collector, Attack Graph, Risk Analyzer, Report Builder, Defense Engine
- Each module can be extended or replaced independently
- **Scalability**: New AI capabilities = new module in ai_engine/

### 4. Data Layer (`app/db/`)
- SQLAlchemy async models with full relationship mapping
- Repository pattern for data access
- Alembic-managed migrations
- **Scalability**: New features = new model + migration

### 5. Background Tasks (`app/tasks/`)
- Celery workers for long-running AI operations
- Tasks: OSINT collection, attack planning, risk assessment, report generation, document validation
- **Scalability**: Add new tasks = new file in tasks/

## Database Schema

### Core Entities
```
User ──────────┬── Engagement ─────┬── ScopeOfEngagement ─── ScopeAsset
               │                   ├── RulesOfEngagement
               │                   ├── DigitalSignature
               │                   ├── UploadedDocument
               │                   ├── OSINTFinding
               │                   ├── KnowledgeGraphNode/Edge
               │                   ├── AttackPath ──── AttackPathStep
               │                   ├── Vulnerability ── VulnerabilityEvidence
               │                   ├── RiskAssessment
               │                   └── Report
               ├── UserSession
               ├── AuditLog
               └── Notification
```

## Security Architecture

### Three-Tier Defense Model
1. **Tier 1 — Gateway Protection**: WAF, signature detection, rate limiting
2. **Tier 2 — AI Behavioral Analysis**: Session monitoring, risk scoring, anomaly detection
3. **Tier 3 — Generative AI Response**: Virtual patches, dynamic firewall, automated alerts

### Authentication Flow
```
Register → OTP Email → Verify OTP → Login → JWT Access + Refresh Token
                                              ↓
                                    Protected API Routes
                                              ↓
                                    Token Refresh (auto)
```

## Scalability Design Decisions

1. **Stateless Backend**: All session state in Redis → horizontal scaling
2. **Async Everything**: FastAPI + SQLAlchemy async → high concurrency
3. **Background Workers**: Celery workers scale independently
4. **API Versioning**: `/api/v1/` prefix → future versions coexist
5. **Feature Modules**: Each feature is self-contained → add new features without touching existing code
6. **Database Migrations**: Alembic version control → safe schema evolution
7. **Frontend Code Splitting**: Lazy-loaded pages → minimal initial bundle
