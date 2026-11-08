# CLAUDE.md

Read `PLAN.md` first — it is the source of truth for scope, stack, phases, DB and API.

## Project
Security scanner SaaS: website + GitHub repo scanning for students, freelancers, small agencies. Monorepo: `/frontend` (Next.js + TS + Tailwind + shadcn/ui), `/backend` (FastAPI + SQLModel + Celery + Redis), Supabase for Postgres + Auth.

## How to work
- Work **one phase / one step at a time**. Show a short plan and wait for my OK before big changes.
- Keep changes small. After each completed step:
  1. Update `CHANGELOG.md` (date, what changed, why)
  2. Update `README.md` if setup/commands changed
  3. Commit with a conventional message (`feat:`, `fix:`, `chore:`, `docs:`)
  4. Once the step is verified (tests, lint and build pass), merge the branch to `main`, push, and delete the branch, unless I say otherwise
- Ask before adding a new dependency.
- Write pytest tests for every scanner check and for the SSRF guard.
- Explain security decisions briefly in code comments — this project is also my portfolio.

## Hard security rules
- Every outbound HTTP request from the backend goes through `backend/app/core/safe_http.py` (SSRF guard). No direct `httpx` calls elsewhere.
- Active checks (exposed files, BaaS probes) run **only on verified domains**. Quick scans are passive only.
- Never store, log or print full secrets — mask them.
- Never commit `.env` or keys. Keep `.env.example` updated.
- Validate all input with Pydantic; verify GitHub webhook signatures.

## Commands
Windows PowerShell. Backend commands run from `backend/`, frontend commands from `frontend/`.

| Task | Command |
|---|---|
| Redis + Postgres | `docker compose up -d redis postgres` (from repo root) |
| API dev server | `.venv/Scripts/python.exe -m uvicorn app.main:app --reload --port 8000` |
| Web dev server | `npm run dev` |
| Backend tests | `.venv/Scripts/python.exe -m pytest` |
| Backend lint | `.venv/Scripts/python.exe -m ruff check .` and `.venv/Scripts/python.exe -m ruff format --check .` |
| Frontend lint | `npm run lint` |
| Frontend build | `npm run build` |
| Worker | `.venv/Scripts/python.exe -m celery -A app.workers.celery_app worker --pool=solo --loglevel=info` |
| Migrations | `.venv/Scripts/python.exe -m alembic upgrade head` |
