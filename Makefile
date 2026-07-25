.PHONY: dev prod test lint deploy clean setup

# ─── Development ──────────────────────────────────────────────
dev:
	docker-compose -f devops/docker/docker-compose.yml -f devops/docker/docker-compose.dev.yml up --build

dev-backend:
	cd backend && uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

dev-frontend:
	cd frontend && npm run dev

# ─── Production ───────────────────────────────────────────────
prod:
	docker-compose -f devops/docker/docker-compose.yml -f devops/docker/docker-compose.prod.yml up -d --build

# ─── Testing ──────────────────────────────────────────────────
test:
	cd backend && pytest tests/ -v --cov=app
	cd frontend && npm test

test-unit:
	cd backend && pytest tests/unit/ -v

test-integration:
	cd backend && pytest tests/integration/ -v

test-e2e:
	cd backend && pytest tests/e2e/ -v

# ─── Linting ──────────────────────────────────────────────────
lint:
	cd backend && ruff check app/ --fix && black app/ && mypy app/
	cd frontend && npm run lint

# ─── Database ─────────────────────────────────────────────────
migrate:
	cd backend && alembic upgrade head

migrate-new:
	cd backend && alembic revision --autogenerate -m "$(msg)"

seed:
	cd backend && python -m app.db.seeders.seed_admin

# ─── Setup ────────────────────────────────────────────────────
setup:
	bash scripts/setup_dev.sh

# ─── Docker ───────────────────────────────────────────────────
build:
	docker-compose build

down:
	docker-compose down

logs:
	docker-compose logs -f

# ─── Cleanup ──────────────────────────────────────────────────
clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name node_modules -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name dist -exec rm -rf {} + 2>/dev/null || true
