# Self-hosting GapScan

This guide takes you from nothing to a first scan on your own machine. Commands are shown for Windows PowerShell and for macOS or Linux.

Run every scanner responsibly: **scan only what you own or have written permission to test.** See [SECURITY.md](../SECURITY.md).

What you need depends on what you want to use:

| Feature | Needs |
|---|---|
| Quick scans | Steps 1 to 3, 7 and 8 |
| Sign-in, verified domains, full scans | Also step 4 |
| Repository scanning | Also steps 4, 5 and 6 |

## 1. Prerequisites

- Python 3.11 or newer
- Node.js 22 or newer
- Docker
- Git 2.31 or newer
- [gitleaks](https://github.com/gitleaks/gitleaks), for repository scanning

**Windows (PowerShell):**

```powershell
winget install --id Python.Python.3.12 -e
winget install --id OpenJS.NodeJS.LTS -e
winget install --id Docker.DockerDesktop -e
winget install --id Git.Git -e
winget install --id Gitleaks.Gitleaks -e
```

Open a new terminal afterwards so the new programs are on your `PATH`.

**macOS:**

```bash
brew install python@3.12 node git gitleaks
brew install --cask docker
```

**Linux:** install Python, Node.js, Git and Docker with your distribution's packages, or from their official sites. Then install gitleaks from its [releases page](https://github.com/gitleaks/gitleaks/releases) and put the binary on your `PATH`.

Check that everything is there. Docker Desktop must be running.

```text
python --version
node --version
docker --version
git --version
gitleaks version
```

On macOS and Linux the first command may be `python3`.

## 2. Clone and install

**Windows (PowerShell):**

```powershell
git clone https://github.com/VivekSharma0502/gapscan.git
cd gapscan
Copy-Item .env.example .env
Copy-Item frontend/.env.example frontend/.env.local
python -m venv backend/.venv
backend/.venv/Scripts/python.exe -m pip install -r backend/requirements.txt
npm --prefix frontend install
```

**macOS or Linux:**

```bash
git clone https://github.com/VivekSharma0502/gapscan.git
cd gapscan
cp .env.example .env
cp frontend/.env.example frontend/.env.local
python3 -m venv backend/.venv
backend/.venv/bin/python -m pip install -r backend/requirements.txt
npm --prefix frontend install
```

If you only want quick scans for now, clear the two Supabase values in each env file so sign-in stays off:

- In `.env`: `SUPABASE_URL=` and `SUPABASE_PUBLISHABLE_KEY=`
- In `frontend/.env.local`: `NEXT_PUBLIC_SUPABASE_URL=` and `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY=`

Never commit `.env` or `frontend/.env.local`. Git already ignores both.

## 3. Start Postgres and Redis

From the repo root:

```text
docker compose up -d redis postgres
```

Both are published on `127.0.0.1` only. The credentials in `docker-compose.yml` are for local development, so don't reuse them anywhere else.

## 4. Create a Supabase project (sign-in)

Supabase is used for sign-in only. App data stays in your Postgres. The backend needs no Supabase secret, so never put the service role key or JWT secret in either env file.

1. Create a project at <https://supabase.com>.
2. Open `https://<project-ref>.supabase.co/auth/v1/.well-known/jwks.json`. The `keys` list must not be empty. GapScan only accepts asymmetric signing keys, so a project on the legacy HS256 secret has to rotate to one first, under Project Settings → JWT Keys.
3. Find the **publishable key** (`sb_publishable_...`) under Project Settings → API Keys.

**GitHub sign-in**

4. In Supabase, go to Authentication → Sign In / Providers → GitHub and copy the Callback URL.
5. At <https://github.com/settings/developers>, create an **OAuth App** with homepage `http://localhost:3000` and that callback URL.
6. Paste its Client ID and a new Client Secret into the same Supabase panel, enable GitHub and save. These two values go nowhere else.

**Magic link sign-in**

7. In Authentication → Sign In / Providers, check that Email is enabled. Supabase's built-in email service has a low rate limit, which is fine for trying GapScan.

**Redirect URLs**

8. In Authentication → URL Configuration, set Site URL to `http://localhost:3000`, and add `http://localhost:3000/auth/callback` to Redirect URLs.

**Env files**

9. In `.env`, set `SUPABASE_URL` and `SUPABASE_PUBLISHABLE_KEY`.
10. In `frontend/.env.local`, set `NEXT_PUBLIC_SUPABASE_URL` and `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY` to the same two values.

Open magic links in the same browser that requested them.

## 5. Create your own GitHub App (repository scanning)

Repository scanning uses a GitHub App, which is separate from the OAuth App used for sign-in. Everyone self-hosting needs their own.

1. **Create a webhook channel.** Open <https://smee.io>, choose "Start a new channel" and copy the URL. It forwards GitHub's webhooks to your machine.
2. **Generate a webhook secret.**

   ```powershell
   # Windows, from the repo root
   backend/.venv/Scripts/python.exe -c "import secrets; print(secrets.token_hex(32))"
   ```

   ```bash
   # macOS or Linux, from the repo root
   backend/.venv/bin/python -c "import secrets; print(secrets.token_hex(32))"
   ```

3. **Create the app** at <https://github.com/settings/apps/new>:

   | Setting | Value |
   |---|---|
   | GitHub App name | Anything available, such as `GapScan (yourname)` |
   | Homepage URL | `http://localhost:3000` |
   | Callback URL | Leave empty |
   | Request user authorization (OAuth) during installation | Off |
   | Setup URL | `http://localhost:3000/repositories/connect` |
   | Redirect on update | On |
   | Webhook | Active |
   | Webhook URL | Your smee URL |
   | Webhook secret | The value from step 2 |
   | Repository permissions | **Contents: Read-only**. **Metadata: Read-only** is added automatically |
   | Other permissions | None |
   | Subscribe to events | **Push** |
   | Where can this GitHub App be installed | Only on this account |

   `installation` and `installation_repositories` have no checkbox, because every app receives them.

4. On the app's page, note the **App ID** and the slug in `github.com/apps/<slug>`.
5. Under Private keys, choose "Generate a private key" to download a `.pem` file.
6. **Convert the key to one line of base64** and copy it.

   ```powershell
   # Windows
   [Convert]::ToBase64String([IO.File]::ReadAllBytes("$HOME\Downloads\<downloaded-file>.pem")) | Set-Clipboard
   ```

   ```bash
   # macOS: copies to the clipboard
   base64 -i ~/Downloads/<downloaded-file>.pem | tr -d '\n' | pbcopy

   # Linux: prints it, so copy the output
   base64 -w0 ~/Downloads/<downloaded-file>.pem
   ```

7. Delete the downloaded `.pem` once step 6 of the next section is done. You can generate a new key at any time.

## 6. Fill in `.env`

Every setting is explained in [`.env.example`](../.env.example) and [`frontend/.env.example`](../frontend/.env.example). For repository scanning, set these in `.env`:

```text
GITHUB_APP_ID=<App ID>
GITHUB_APP_SLUG=<slug>
GITHUB_APP_PRIVATE_KEY_B64=<the base64 line>
GITHUB_WEBHOOK_SECRET=<the value from step 2>
```

Set your own scanner link, so a site owner can find out who is scanning them:

```text
SCANNER_USER_AGENT=GapScanBot/1.0 (+https://example.com/about-our-scanner)
```

## 7. Run database migrations

**Windows (PowerShell):**

```powershell
cd backend
.venv/Scripts/python.exe -m alembic upgrade head
cd ..
```

**macOS or Linux:**

```bash
cd backend
.venv/bin/python -m alembic upgrade head
cd ..
```

Run this again whenever an update adds a migration.

## 8. Run GapScan

Use three terminals, plus a fourth for webhooks.

**Windows (PowerShell):**

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

# Terminal 4: optional, so pushes trigger repository scans
npx smee-client --url <your smee URL> --target http://127.0.0.1:8000/api/github/webhook
```

**macOS or Linux:**

```bash
# Terminal 1: API on http://localhost:8000
cd backend
.venv/bin/python -m uvicorn app.main:app --reload --port 8000

# Terminal 2: scan worker
cd backend
.venv/bin/python -m celery -A app.workers.celery_app worker --loglevel=info -Q celery,repo_scans

# Terminal 3: web app on http://localhost:3000
cd frontend
npm run dev

# Terminal 4: optional, so pushes trigger repository scans
npx smee-client --url <your smee URL> --target http://127.0.0.1:8000/api/github/webhook
```

About the worker flags:

- `--pool=solo` is required on Windows, where Celery's default pool doesn't work. It runs one job at a time, so a long repository scan delays website scans.
- `-Q celery,repo_scans` serves both website and repository scans. Without it, repository scans stay queued.
- Without a worker, scans stay queued and are marked failed after 5 minutes.

## 9. Your first scan

**Quick scan, with no account:** open <http://localhost:3000> and enter a domain. It runs passive checks only.

**Verify a domain and run a full scan:**

1. Choose **Sign in**, then **Continue with GitHub** or **Email me a sign-in link**.
2. Open **My domains** from the user menu, and choose **Add domain**. Each account can have 3 domains.
3. Prove you control it using one of the two methods shown on its card:
   - A DNS TXT record at `_gapscan-verify.<hostname>` containing `gapscan-verify=<token>`
   - A file at `https://<hostname>/.well-known/gapscan-verify.txt` containing only the token
4. Verify the domain from its card. DNS changes can take a few minutes to appear.
5. Start a full scan. GapScan proves ownership again before every full scan.
6. If the report lists Firebase or Supabase backends, confirm the ones that are yours on **My domains**. Nothing is sent to a backend until you do.

**Scan a repository:**

1. Sign in with GitHub, using the account that owns the repositories. Personal accounts only for now.
2. Open <http://localhost:3000/repositories>, choose **Connect GitHub** and pick the repositories to allow.
3. Choose **Scan now** to check the whole git history. Findings appear under **View findings**.
4. With smee running, each push scans only its new commits. A first scan, a force-push or a missed push covers the whole history.

Repository scans are capped at 500 MB reported size, 1 GB on disk, 3 minutes to clone, 5 minutes to search, 5 MB per file and 1,000 findings. A scan that hits a cap finishes as incomplete and says why.

## Troubleshooting

**DNS lookups time out, or scans and verification are very slow (UDP port 53 blocked)**

Some networks block ordinary DNS on UDP port 53, and Windows machines can list dead DNS servers from disconnected adapters. GapScan falls back from UDP to TCP, DNS-over-HTTPS and then the operating system, but it waits at each step. Set these in `.env`, then restart the API and the worker:

```text
SCANNER_DNS_SERVERS=1.1.1.1,8.8.8.8
SCANNER_DNS_TIMEOUT_SECONDS=2
```

**Code or `.env` changes have no effect, or port 8000 is already in use (a stale uvicorn)**

An old uvicorn process may still be answering on port 8000. Find it and stop it, then start the API again.

```powershell
# Windows
Get-NetTCPConnection -LocalPort 8000 -State Listen | Select-Object OwningProcess
Stop-Process -Id <OwningProcess>
```

```bash
# macOS or Linux
lsof -ti tcp:8000
kill <pid>
```

`--reload` only watches code, so restart the API after editing `.env`.

**The worker still behaves the old way after a code change**

The worker doesn't reload. Stop it and start it again after any backend code or `.env` change.

**The page says "We couldn't reach the scanner", but the API is running (Brave Shields)**

Brave Shields can block the page's requests to the API or to Supabase. Turn Shields off for `localhost` using the lion icon in the address bar, then reload. Other ad blockers can do the same.

**A Vercel site shows "Read 0 of 1 scripts", or checks are skipped (Vercel bot checkpoint)**

Vercel's Security Checkpoint answered instead of the site, with a 403 and an `x-vercel-mitigated` header. GapScan stops requesting a site at its first challenge rather than trying to get around it, so the affected checks show as skipped and the report says why. If the site is yours, add a [Vercel firewall rule](https://vercel.com/docs/vercel-firewall/vercel-waf/custom-rules) that lets your scanner through, then scan again. Cloudflare has an [equivalent](https://developers.cloudflare.com/waf/custom-rules/skip/).

**A webhook returns 401**

Restart the API if you changed `GITHUB_WEBHOOK_SECRET`, and check it matches the secret on GitHub. smee re-encodes the JSON it forwards, so a delivery containing escapes like `é` or `\/` can fail its signature check. This only affects smee.

**Scans stay queued, or are marked failed after 5 minutes**

The worker isn't running, or it was started without `-Q celery,repo_scans`.

**Sign-in fails after the GitHub redirect**

Check that `http://localhost:3000/auth/callback` is in Supabase's Redirect URLs, and that the JWKS URL in step 4 lists at least one key.

## Production notes

These are starting points. Read [SECURITY.md](../SECURITY.md) before exposing a deployment.

Behind a reverse proxy or load balancer, tell uvicorn which proxy to trust, so the API sees each visitor's real IP:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --forwarded-allow-ips="<your proxy's IP or CIDR>"
```

- Without `--forwarded-allow-ips`, every visitor appears to come from the proxy, and they all share one quick-scan limit of 5 per minute.
- Don't use `*` unless the proxy is the only way to reach the app. Otherwise a client can forge `X-Forwarded-For` and get around the limit.
- Set `CORS_ORIGINS` to your site's address, and use your own `DATABASE_URL` and `REDIS_URL`.
- On Linux, run the worker without `--pool=solo`. The default pool runs scans in parallel and enforces the task time limit.
- Run a separate worker with `-Q repo_scans`, so repository scans can't hold up website scans, and install `git` and `gitleaks` on it.
- Create a separate GitHub App with its own key and webhook secret. Point its webhook at `https://<your API>/api/github/webhook` and its Setup URL at `https://<your site>/repositories/connect`.
- Add your site's URL and `/auth/callback` address to Supabase's URL Configuration.
- If you modify GapScan and offer it over a network, the AGPL requires you to offer your users the source code of your version.
