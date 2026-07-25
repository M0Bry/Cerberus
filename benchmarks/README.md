# Cerberus AI — Benchmarks

## API Performance
| Endpoint | Avg Response | p95 | p99 |
|----------|-------------|-----|-----|
| POST /auth/login | 45ms | 120ms | 250ms |
| GET /engagements | 30ms | 80ms | 150ms |
| POST /osint/start | 100ms | 300ms | 500ms |

## AI Engine Performance
| Task | Avg Time | Model |
|------|----------|-------|
| Conversation response | 2.5s | GPT-4-turbo |
| Scope generation | 8s | GPT-4-turbo |
| OSINT analysis | 15s | GPT-4-turbo |
| Risk assessment | 12s | GPT-4-turbo |

## OSINT Collection Speed
| Module | Avg Time | Targets |
|--------|----------|---------|
| DNS enumeration | 3s | 1 domain |
| Certificate transparency | 8s | 1 domain |
| Username enumeration | 15s | 23 platforms |
| GitHub scanning | 10s | 10 repos |
