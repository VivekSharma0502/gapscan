# GapScan

Security checks for websites and GitHub repos, built for students, freelancers and small agencies.

See `PLAN.md` for scope and roadmap, and `CHANGELOG.md` for history.

The product name is set once, in `product.json`. The backend and frontend both read it, and both need the file when deployed. Supabase's sign-in emails are edited in the Supabase dashboard, so a rename needs a manual change there too.

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
- Git 2.31 or newer, and [gitleaks](https://github.com/gitleaks/gitleaks) for repo scanning (`winget install --id Gitleaks.Gitleaks -e`, then open a new terminal)

## Setup

Commands are for Windows PowerShell, run from the repo root.

```powershell
# 1. Env files (never commit the copies)
Copy-Item .env.example .env
"NEXT_PUBLIC_API_URL=http://localhost:8000" | Out-File -Encoding ascii frontend/.env.local
# Then add the Supabase values: see "Sign-in setup" below.

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

## Sign-in setup

Supabase is used for Auth only. App data stays in the local Postgres. Scanning works without this, but sign-in stays off.

1. Open `https://<project-ref>.supabase.co/auth/v1/.well-known/jwks.json`. `keys` must not be empty. GapScan only accepts asymmetric signing keys, so a project on the legacy HS256 secret has to rotate to one first.
2. In Supabase, go to Authentication → Sign In / Providers → GitHub and copy the Callback URL.
3. At <https://github.com/settings/developers>, create an OAuth App with homepage `http://localhost:3000` and that callback URL.
4. Paste its Client ID and a new Client Secret into the same Supabase panel, enable GitHub and save. These two values go nowhere else.
5. In Authentication → URL Configuration, set Site URL to `http://localhost:3000` and add `http://localhost:3000/auth/callback` to Redirect URLs.
6. Add `SUPABASE_URL` to `.env`, and `NEXT_PUBLIC_SUPABASE_URL` and `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY` to `frontend/.env.local`. See `.env.example`. Restart both dev servers.

The backend needs no Supabase secret. Don't add the service role key or the JWT secret to either file. Magic links must be opened in the browser that requested them.

## GitHub App setup

Repo scanning uses a GitHub App. This is separate from the OAuth App used for sign-in.

1. Open <https://smee.io>, choose "Start a new channel" and copy the URL. It forwards GitHub's webhooks to your machine.
2. Generate a webhook secret, from `backend/`: `.venv/Scripts/python.exe -c "import secrets; print(secrets.token_hex(32))"`
3. At <https://github.com/settings/apps/new>, create the app:
   - GitHub App name: `GapScan (dev)`. Homepage URL: `http://localhost:3000`.
   - Setup URL: `http://localhost:3000/repositories/connect`, and tick "Redirect on update".
   - Leave Callback URL empty and "Request user authorization (OAuth) during installation" off.
   - Webhook: active. URL: the smee URL. Secret: the value from step 2.
   - Repository permissions: Contents read-only. Metadata read-only is added automatically.
   - Subscribe to events: Push. `installation` and `installation_repositories` have no checkbox, because every app receives them.
   - Where can this GitHub App be installed: Only on this account.
4. On the app's page, note the App ID and the slug in `github.com/apps/<slug>`. Under Private keys, choose "Generate a private key" to download a `.pem`.
5. Copy the key to the clipboard as one line of base64: `[Convert]::ToBase64String([IO.File]::ReadAllBytes("$HOME\Downloads\<downloaded-file>.pem")) | Set-Clipboard`
6. In the root `.env`, set `GITHUB_APP_ID`, `GITHUB_APP_SLUG`, `GITHUB_APP_PRIVATE_KEY_B64` (paste) and `GITHUB_WEBHOOK_SECRET` (step 2). Copy `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY` into `SUPABASE_PUBLISHABLE_KEY` as well. Then delete the downloaded `.pem`, since a new key can be generated at any time.

To receive webhooks locally, keep this running in a fourth terminal: `npx smee-client --url <smee URL> --target http://127.0.0.1:8000/api/github/webhook`

## Run

Use three terminals, plus a fourth for smee if you want pushes to trigger repo scans.

```powershell
# Terminal 1: API on http://localhost:8000
cd backend
.venv/Scripts/python.exe -m uvicorn app.main:app --reload --port 8000

# Terminal 2: scan worker
cd backend
.venv/Scripts/python.exe -m celery -A app.workers.celery_app worker --pool=solo --loglevel=info -Q celery,repo_scans

# Terminal 3: web app on http://localhost:3000
cd frontend
npm run dev
```

Open http://localhost:3000 and enter a domain to run a quick scan.

The worker runs the scans, so without it they stay queued and are marked failed after 5 minutes. `--pool=solo` is required on Windows, where Celery's default pool doesn't work, and runs one scan at a time. Restart the worker after changing its code, because it doesn't reload. `-Q celery,repo_scans` makes it serve website scans and repo scans. Without it, repo scans stay queued. Because `--pool=solo` runs one job at a time, a long repo scan delays website scans locally.

`--reload` only watches code, so restart the API after editing `.env`.

## Repo scanning

Needs the sign-in and GitHub App setup above, and `git` and `gitleaks` on the worker's PATH. Sign in with GitHub using the account that owns the repos, because an installation is only linked when its account matches the one you signed in with. Personal accounts only for now.

1. Open <http://localhost:3000/repositories>, choose **Connect GitHub** and pick the repositories to allow.
2. Choose **Scan now** to check a repo's whole git history. Findings appear under **View findings**, grouped by severity, with steps for replacing each key.
3. With smee running, each push scans only its new commits. A repo's first scan, a force-push or a missed push covers the whole history.

Scans are capped at 500 MB reported size, 1 GB on disk, 3 minutes to clone, 5 minutes to search, 5 MB per file and 1,000 findings. A scan that hits a cap finishes as incomplete and says why.

If a webhook returns 401:
- Restart the API if you changed `GITHUB_WEBHOOK_SECRET`, and check it matches the secret on GitHub. If uvicorn reports the port is in use, an old process is still answering on it.
- smee re-encodes the JSON it forwards, so a delivery containing escapes like `é` or `\/` can fail its signature check locally. This only affects smee, because in production GitHub posts straight to the API.

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

## Deploy

Behind a reverse proxy or a platform load balancer, tell uvicorn which proxy to trust, so the API sees each visitor's real IP:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --forwarded-allow-ips="<your proxy's IP or CIDR>"
```

- Without `--forwarded-allow-ips`, every visitor appears to come from the proxy and they all share one `POST /api/scans/quick` limit of 5 per minute.
- Don't use `*` unless the proxy is the only way to reach the app. Otherwise a client can forge `X-Forwarded-For` and get around the limit.

Run the worker without `--pool=solo` on Linux. The default pool runs scans in parallel and enforces the task time limit. In production, run a separate worker with `-Q repo_scans` so repo scans can't hold up website scans, and install `git` and `gitleaks` on it.

For repo scanning in production, create a separate GitHub App with its own key and webhook secret. Point its webhook at `https://<your API>/api/github/webhook` and its Setup URL at `https://<your site>/repositories/connect`, and allow it to be installed on any account.
