# ScanKit

Security checks for websites and GitHub repos, built for students, freelancers and small agencies.

See `PLAN.md` for scope and roadmap, and `CHANGELOG.md` for history.

## Layout

| Path | What |
|---|---|
| `frontend/` | Next.js (App Router), TypeScript, Tailwind, shadcn/ui |
| `backend/` | FastAPI, SQLModel |
| `docker-compose.yml` | Redis and Postgres for local development |

## Prerequisites

- Node.js 22 or newer
- Python 3.11 or newer
- Docker

## Setup

Commands are for Windows PowerShell, run from the repo root.

```powershell
# 1. Env files (never commit the copies)
Copy-Item .env.example .env
"NEXT_PUBLIC_API_URL=http://localhost:8000" | Out-File -Encoding ascii frontend/.env.local

# 2. Redis and Postgres
docker compose up -d redis postgres

# 3. Backend
python -m venv backend/.venv
backend/.venv/Scripts/python.exe -m pip install -r backend/requirements-dev.txt

# 4. Database tables, from backend/
cd backend
.venv/Scripts/python.exe -m alembic upgrade head
cd ..

# 5. Frontend
npm --prefix frontend install
```

After pulling changes that add a migration, run `alembic upgrade head` again. To create one after changing a model, run `.venv/Scripts/python.exe -m alembic revision --autogenerate -m "describe the change"` from `backend/` and review the generated file.

Scan DNS lookups fall back automatically from UDP to TCP, DNS-over-HTTPS and then the operating system. If your network blocks UDP DNS, set `SCANNER_DNS_SERVERS=1.1.1.1,8.8.8.8` and a lower `SCANNER_DNS_TIMEOUT_SECONDS` in `.env` to reach the working fallback sooner.

## Run

Use three terminals.

```powershell
# Terminal 1: API on http://localhost:8000
cd backend
.venv/Scripts/python.exe -m uvicorn app.main:app --reload --port 8000

# Terminal 2: scan worker
cd backend
.venv/Scripts/python.exe -m celery -A app.workers.celery_app worker --pool=solo --loglevel=info

# Terminal 3: web app on http://localhost:3000
cd frontend
npm run dev
```

Open http://localhost:3000. The page should show **API status: OK**.

The worker runs the scans, so without it they stay queued and are marked failed after 5 minutes. `--pool=solo` is required on Windows, where Celery's default pool doesn't work, and runs one scan at a time. Restart the worker after changing its code, because it doesn't reload.

## Tests and lint

```powershell
# Backend, from backend/
.venv/Scripts/python.exe -m pytest
.venv/Scripts/python.exe -m ruff check .
.venv/Scripts/python.exe -m ruff format --check .

# Frontend, from frontend/
npm run lint
npm run build
```
