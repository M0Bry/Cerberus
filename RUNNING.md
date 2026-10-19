# Running Cerberus AI locally

Starts **Postgres → API → seed → frontend**. Works on Windows (PowerShell),
macOS and Linux. The API auto-creates the full database schema on startup,
so a fresh database only needs the seed script for plans + admin.

## Prerequisites (install once)

| Tool | Version | Where |
|---|---|---|
| Python | **3.11 or 3.12** (not 3.13 — pinned deps have no 3.13 wheels) | https://python.org |
| Node.js | 18+ (20+ recommended) | https://nodejs.org |
| PostgreSQL | 14+ (17 recommended) | Windows: `winget install PostgreSQL.PostgreSQL.17` · Linux: `sudo apt-get install postgresql` · macOS: `brew install postgresql@17` |

---

## Windows (PowerShell)

All commands below assume you're in the folder you extracted the project to:

```powershell
cd C:\path\to\Cerberus
```

### 1) Postgres — one-time setup

Postgres is installed as a Windows service (starts automatically with Windows).
Create the role + database. If `psql` is not on your PATH, use the full path
`C:\Program Files\PostgreSQL\17\bin\psql.exe`:

```powershell
psql -U postgres -c "CREATE ROLE cerberus LOGIN PASSWORD 'cerberus_secret';" -c "CREATE DATABASE cerberus OWNER cerberus;"
```

It asks for the **postgres superuser password** you chose during the Postgres
installation. (If the role already exists, `psql` prints a notice and moves on.)

### 2) Backend `.env`

```powershell
cd backend
Copy-Item .env.example .env
notepad .env
```

Set **`SECRET_KEY`** to a random 64-char string (the app refuses to start with
the placeholder). Generate one with:

```powershell
-join ((48..57)+(97..122) | Get-Random -Count 64 | ForEach-Object {[char]$_})
```

Leave `SMTP_USER` / `SMTP_FROM_EMAIL` **empty** — the app then prints every
OTP code to the API terminal instead of sending mail (ideal for testing).
`DATABASE_URL` already points at `localhost:5432/cerberus` — matches step 1.

### 3) Python dependencies

```powershell
py -3 -m venv .venv
.venv\Scripts\pip install -r requirements.txt
```

### 4) Start the API  *(terminal 1 — leave it running)*

```powershell
.venv\Scripts\uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Wait for `Application startup complete.` — the schema is created here
automatically on a fresh database. Check: http://localhost:8000/health

### 5) Seed plans + admin  *(terminal 2)*

```powershell
.venv\Scripts\python ..\scripts\live_tests\res_seed_db.py
```

Prints `plans seeded` / `admin created` (or `admin updated` on re-runs — it's
idempotent). Reads `DATABASE_URL` from `backend/.env` itself, so it works from
any folder.

### 6) Start the frontend  *(terminal 2 or 3 — leave it running)*

```powershell
cd ..\frontend
npm install
npm run dev
```

Open **http://localhost:3000** — the Vite dev server proxies `/api` to the
backend on :8000, so no extra configuration is needed.

---

## Linux / macOS

```bash
cd Cerberus

# 1) Postgres — one-time
sudo -u postgres psql -c "CREATE ROLE cerberus LOGIN PASSWORD 'cerberus_secret';" \
                      -c "CREATE DATABASE cerberus OWNER cerberus;"
sudo pg_ctlcluster 17 main start        # Debian/Ubuntu only, if the cluster is down

# 2) Backend env
cd backend
cp .env.example .env
python3 -c "import secrets; print(secrets.token_hex(32))"   # paste into SECRET_KEY

# 3) Python deps
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt

# 4) API  (terminal 1)
./.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000

# 5) Seed  (terminal 2)
./.venv/bin/python ../scripts/live_tests/res_seed_db.py

# 6) Frontend  (terminal 2/3)
cd ../frontend && npm install && npm run dev
```

---

## Accounts

| Role | Email | Password |
|---|---|---|
| Admin | `admin@cerberus-ai.com` | `Admin!zoHBF-1dlBnVVK22` |

Admin login is two-step (password → OTP). With the console email provider the
**OTP is printed in the API terminal** (look for `[CERBERUS DEV] Email`).
Regular users: register through the UI — the verification OTP also appears in
the API terminal.

## Troubleshooting (Windows)

**pip fails with `Preparing metadata (pyproject.toml) ... error` / tries to
"build from source" (you see `tar.gz` downloads, e.g. for `scikit-learn`
or `asyncpg`):** you're on Python 3.13. The pinned dependency versions ship
prebuilt Windows wheels only up to 3.12, so pip falls back to compiling from
source and fails without Visual Studio Build Tools. Fix:

```powershell
winget install Python.Python.3.12
# close + reopen PowerShell, then in backend\:
Remove-Item -Recurse -Force .venv
py -3.12 -m venv .venv
.venv\Scripts\pip install -r requirements.txt
```

With 3.12 every package installs from a ready-made wheel — no compiler needed.

## Operational notes

- **Run the API from the `backend/` folder** — `.env` and `UPLOAD_DIR` are
  resolved relative to the working directory.
- The API terminal must stay open; OTPs and defense alerts are logged there.
- **Stopping everything:** `Ctrl+C` in each terminal (frontend, then API).
  Postgres keeps running as a service — data persists between runs.
- **Wipe and start over:** drop & recreate the `cerberus` database, restart
  the API (schema re-creates itself), re-run the seed script.
- The live security QA suite lives in `scripts/live_tests/` (see its README) —
  it needs the API + DB from above and a few extra environment overrides.
