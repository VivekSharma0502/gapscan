# PLAN.md — Security Scanner SaaS (GapScan, name set in `product.json`)

## One-liner
Security check for apps built by students, freelancers and small agencies — website + GitHub repo scanning in one dashboard, plain-language fixes, priced in INR.

## Who it's for
- Students / indie devs shipping on Firebase, Supabase, Vercel, Netlify
- Freelancers & small agencies who build sites for clients
- Small business owners (plain-language reports)

## What makes us different (keep these in every decision)
1. **BaaS misconfig checks** — open Firebase rules, Supabase tables without RLS, exposed `.env`, public source maps
2. **Repo ↔ site correlation** — secret/config found in repo → check if the live backend is actually exposed
3. **Platform-specific fixes** — copy-paste snippets for Vercel / Netlify / nginx / Cloudflare / Firebase / Supabase
4. **Agency mode** — white-label PDF client reports
5. **INR pricing** via Razorpay/UPI
6. **Plain language**, later Hindi + Gujarati
7. **Embeddable score badge** (growth loop)

Don't reinvent engines: use **gitleaks** for secrets; write our own checks for headers/TLS/DNS (MDN Observatory logic as reference).

---

## Stack
| Layer | Choice |
|---|---|
| Frontend | Next.js (App Router) + TypeScript, Tailwind, shadcn/ui, TanStack Query, react-hook-form + zod, Recharts, Lucide |
| Backend | FastAPI (Python 3.11+), Pydantic, SQLModel + Alembic, httpx, dnspython |
| Jobs | Redis + Celery (+ Celery Beat for scheduled rescans) |
| DB + Auth | Supabase (Postgres + Auth, "Sign in with GitHub"); FastAPI verifies Supabase JWT |
| Repo scanning | GitHub App + webhooks, gitleaks |
| Notifications | Resend (email), Telegram Bot API |
| Reports | WeasyPrint (HTML → PDF) |
| Payments | Razorpay (Phase 5) |
| Hosting | Frontend → Vercel · Backend + worker + Redis → Railway/Render or VPS (Docker Compose) · DNS → Cloudflare |

## Repo layout
```
/frontend          Next.js app
/backend
  /app
    /api           FastAPI routers
    /core          config, auth, safe_http (SSRF guard), rate limit
    /checks        one file per check group (tls.py, headers.py, cookies.py, dns_email.py, exposure.py, cms.py, baas.py)
    /models        SQLModel tables
    /workers       Celery app + tasks
    /reports       PDF templates
  /tests
docker-compose.yml (redis, optional local postgres)
PLAN.md  CLAUDE.md  README.md  CHANGELOG.md  .env.example
```

---

## Phases

### Phase 0 — Scaffold (Day 1–2)
- Monorepo structure above, Next.js + FastAPI hello-world, docker-compose (Redis)
- `.env.example`, README (setup steps), CHANGELOG, `.gitignore`
- Health route `GET /api/health`, frontend calls it

### Phase 1 — Web scanner + quick scan (Week 1–2)
- `safe_http` client with SSRF guard (see Security rules) — **build first, everything uses it**
- Check registry: each check returns `{check_id, category, severity, title, evidence, fix}`
- Passive checks (allowed on any domain, quick scan):
  - TLS: valid cert, days to expiry, TLS version, HTTP→HTTPS redirect, HSTS
  - Headers: CSP, frame-ancestors/X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, server version leak
  - Cookies: Secure / HttpOnly / SameSite
  - DNS/email: SPF, DMARC, CAA
  - CMS: WordPress version detection
- Score + grade (see Scoring)
- Landing page: enter domain → live progress (poll scan status) → teaser results (top 3 + score) → "sign up for full report"
- Findings UI: grouped by severity, each with *What it means* + *How to fix* (tabs per platform)

### Phase 2 — Accounts + verified domains (Week 2–3)
- Supabase Auth (GitHub login + email)
- Add domain (3 per user for now) → prove ownership with a DNS TXT record at `_gapscan-verify.<hostname>` containing `gapscan-verify=<token>`, or a file at `https://<hostname>/.well-known/gapscan-verify.txt` containing only the token → verify. Domains added before the rename also keep accepting the `scankit-verify` names. Ownership is proven again before every full scan
- Active checks (**verified domains only**): `/.env`, `/.git/HEAD`, `.DS_Store`, backup files, source maps, directory listing
- Dashboard: domains, latest score, score history chart, scan history

### Phase 3 — Repos + BaaS + correlation (Week 3–4)
- GitHub App: install → list repos → scan with gitleaks; webhook on `push` scans new commits
- Store only masked secrets + file/line/commit. gitleaks runs with `--redact`, so the mask is a fixed per-provider prefix (`AKIA****`) and no characters of the real secret are kept. Findings are deduped per repo on gitleaks' fingerprint, so a rescan keeps the first-seen date
- Personal-account installs only for now. Organization installs need GitHub's user authorization during install (later)
- BaaS checks (verified domains only):
  - Firebase config in JS bundle → RTDB `/.json` readable? Firestore/Storage rules open?
  - Supabase URL + anon key in bundle → tables readable without RLS?
- Correlation: repo finding mentions a project/domain the user owns → link findings, raise severity if live exposure confirmed

### Phase 4 — Monitoring + reports (Week 5)
- Celery Beat scheduled rescans (weekly free / daily paid)
- Alerts on new High/Critical + SSL/domain expiry (email, Telegram)
- PDF report (client-ready)
- Badge `GET /api/badge/{domain}.svg`
- TODO: check the detected WordPress version against the official WordPress latest-version API, through `safe_http`, and raise severity when it is outdated
- TODO: "CSP quality" check that flags `unsafe-inline`, `unsafe-eval` and wildcard sources. `headers.csp_weak` already does this at low severity for `script-src`/`default-src` and exact broad sources (`*`, `http:`, `https:`, `data:`), so extend it to other directives such as `style-src`, partial wildcards such as `*.example.com` and `https://*`, and severity based on how much each source weakens the policy

### Phase 5 — Monetize + polish (later)
- Razorpay plans, agency white-label (logo/name on PDF), Hindi/Gujarati report text, team members

---

## Database (draft)
- **profiles**: id (= Supabase uid), email, name, plan, created_at
- **domains**: id, owner_id, hostname (unique per owner, not globally), verify_token, verified_at, verified_method, created_at
- **github_install_states**: id, owner_id, token_hash, expires_at, created_at (one-time, ties an install redirect to the user who started it)
- **github_installations**: id, owner_id, installation_id, account_id, account_login, suspended_at, created_at
- **repos**: id, owner_id, installation_id, github_repo_id, full_name, is_private, first_full_scan_at, needs_full_scan, created_at
- **github_deliveries**: delivery_id, received_at (webhook replay protection)
- **scans**: id, owner_id (nullable = anonymous), target_type (web|repo), domain_id, repo_id, before_sha, after_sha, target, mode (quick|full), status (queued|running|done|failed), progress_json, result_status (complete|partial|incomplete), score, grade, grade_cap_reason, score_label, incomplete_reason, skipped_json, created_at, started_at, finished_at
- **findings**: id, scan_id, check_id, category, severity (critical|high|medium|low|info), title, evidence_masked, location, linked_finding_id, repo_id, rule_id, file_path, line, commit_sha, fingerprint, created_at (first seen, for repo findings)
- **scan_claims**: id, scan_id, token_hash, created_at, claimed_by, claimed_at (one per anonymous request, redeemed after signup. A redeemed row grants that user the full report, since scans within the reuse window are shared)
- **notification_settings**: owner_id, email_enabled, telegram_chat_id, min_severity
- Check text (what it means / fixes per platform) lives in code, keyed by `check_id`.

## API (draft)
| Method | Route | Notes |
|---|---|---|
| GET | /api/health | |
| POST | /api/scans/quick | anonymous, 5/min per IP, passive checks only. Returns a scan of the same hostname from the last 10 minutes instead of starting one, max 20 new scans per hostname per hour. Returns a `claim_token` to anonymous callers |
| POST | /api/scans/claim | auth, 20/min per IP. Redeems up to 20 claim tokens for the signed-in user |
| GET | /api/scans/{id} | status + progress + score + findings (top 3 unless the viewer owns the scan or holds a redeemed claim). Full scans return 404 to anyone but their owner |
| GET | /api/domains | auth |
| POST | /api/domains | returns the token and both verification methods |
| DELETE | /api/domains/{id} | auth. Past scans stay readable by their owner |
| POST | /api/domains/{id}/verify | DNS TXT lookup and file fetch, with a reason for each failure |
| POST | /api/domains/{id}/scan | full scan, verified only |
| GET | /api/repos | auth |
| POST | /api/repos/{id}/scan | auth |
| POST | /api/github/webhook | verify `X-Hub-Signature-256` |
| GET | /api/dashboard | auth. Per-domain standing and trend, plus recent scans |
| GET | /api/domains/{id}/scans | auth, owner only. Full scans, paginated (`limit`, `offset`, `scored_only`) |
| GET | /api/scans/{id}/report.pdf | auth |
| PUT | /api/settings/notifications | auth |
| GET | /api/badge/{domain}.svg | public |

## Scoring
Start at 100. Deduct per finding: critical −25, high −15, medium −7, low −2, info 0. Floor 0.
Grades: A+ ≥95, A ≥85, B ≥70, C ≥55, D ≥40, F <40.
Grade caps, on top of the points (the numeric score stays as calculated): no HTTPS or an expired/untrusted certificate caps the grade at F, and any other critical finding caps it at D. A scan that couldn't read the site has no score, and gets a grade only when one of the F caps applies.

## Security rules (non-negotiable)
- **SSRF guard** on every outbound request: resolve DNS, block private/loopback/link-local/reserved/multicast IPs (v4 + v6), re-check after each redirect, max 5 redirects, timeouts, response size cap
- The repo scanner's `git clone` can't use the guard, so it is the one exception: `https://github.com/<owner>/<name>.git` only, redirects off, name from a GitHub API response
- **Ownership** required for active + BaaS checks (DNS TXT for domains, GitHub App install for repos)
- **Rate limiting** (slowapi) — strict on `/api/scans/quick`
- Never store or log full secrets; mask everything
- GitHub App private key in env only; use short-lived installation tokens, don't store user tokens
- Verify webhook signatures; validate all input with Pydantic; locked-down CORS
- Scanner sends an honest User-Agent with a link to an "about our scanner" page

## Pricing (draft, Phase 5)
- Free: 1 domain, 3 repos, weekly rescans
- Pro ₹299/mo: 5 domains, unlimited repos, daily rescans, alerts, PDF
- Agency ₹999/mo: 25 domains, white-label reports

## Validate early
After Phase 1: run free reports for 5 local businesses / student projects, collect feedback before building payments.
