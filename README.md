# ScanKit

Security checks for websites and GitHub repos, built for students, freelancers and small agencies.

See `PLAN.md` for scope and roadmap, and `CHANGELOG.md` for history.

## Layout

| Path | What |
|---|---|
| `frontend/` | Next.js (App Router), TypeScript, Tailwind, shadcn/ui |
| `backend/` | FastAPI, SQLModel |
| `docker-compose.yml` | Redis for local development |

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

# 2. Redis
docker compose up -d redis

# 3. Backend
python -m venv backend/.venv
backend/.venv/Scripts/python.exe -m pip install -r backend/requirements-dev.txt

# 4. Frontend
npm --prefix frontend install
```

Scan DNS lookups fall back automatically from UDP to TCP, DNS-over-HTTPS and then the operating system. If your network blocks UDP DNS, set `SCANNER_DNS_SERVERS=1.1.1.1,8.8.8.8` and a lower `SCANNER_DNS_TIMEOUT_SECONDS` in `.env` to reach the working fallback sooner.

## Run

Use two terminals.

```powershell
# Terminal 1: API on http://localhost:8000
cd backend
.venv/Scripts/python.exe -m uvicorn app.main:app --reload --port 8000

# Terminal 2: web app on http://localhost:3000
cd frontend
npm run dev
```

Open http://localhost:3000. The page should show **API status: OK**.

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
