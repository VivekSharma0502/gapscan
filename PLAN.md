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
    /repos         repo secret scanning: git + gitleaks runner, report parsing, rotation guides
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

**Step 3a: GitHub repo secret scanning. Done, verified end to end on 2026-11-10.**
- [x] GitHub App: install → list repos → scan with gitleaks; webhook on `push` scans new commits
- [x] Installation linking with a one-time state, checked against the GitHub account the user signed in with
- [x] Store only masked secrets + file/line/commit. gitleaks runs with `--redact`, so the mask is a fixed per-provider prefix (`AKIA****`) and no characters of the real secret are kept. Findings are deduped per repo on gitleaks' fingerprint, so a rescan keeps the first-seen date
- [x] Rotation guides per provider, checked against each provider's official docs and linked from each finding
- [x] Repositories page, findings page and dashboard section
- Personal-account installs only for now. Organization installs need GitHub's user authorization during install (later)

**Step 3b: BaaS misconfiguration checks (verified domains only, read-only probes)**
- [x] Discovery: Firebase and Supabase backends in the homepage and same-origin scripts, stored per domain. A server-only Supabase key in a script is critical
- [x] "These are mine" confirmation on the My domains page
- [x] Firebase RTDB root readable → critical (stores yes/no + key count). Storage listing → high
- [x] "Check backends" runs only the probes for confirmed backends, so a blocked website can't stop them. A refused probe is reported as an explicit "Checked" line
- [x] Supabase tables named by `.from()` in scripts, checked with HEAD. Readable → high, with a per-table "meant to be public" option that makes it info and stops it affecting the grade
- [x] Plain-language fixes with rule snippets
- Supabase probes need the public key from the site's own code, so they run in full scans only and "Check backends" covers Firebase
- Nothing is sent to a backend until the domain's owner confirms it's theirs, because a verified site's code can name someone else's project
- Firestore isn't covered, because probing it needs collection names

**Step 3c: repo and site correlation (combines stored data, no new outbound requests)**
- [x] Tables and migration
- [x] Local identifier extraction during repo scans
- [x] Site side: keep the Firebase project ID, and tie service-key findings to a project
- [x] Correlation logic and link suggestions
- [x] Repo-to-domain link API and screen
- [x] Combined card with rotate and history-purge steps
- [ ] Scoring
- Matching happens only within one owner's repos and verified domains, on project identifiers. Keys can't be compared, because no part of one is kept
- A Supabase admin key, or a Firebase service account whose `project_id` matches, is critical. A Firebase web config match is info
- A "likely" match (the repo names only one project) shows as critical (likely), with no score deduction and no grade cap. Only confirmed matches affect the site score
- A confirmed match counts once per project, and not at all if that site scan already has a service-key finding for it
- The owner can mark a key as rotated, recording who and when. A fingerprint not covered by that rotation opens a new card. A key copied to a new commit or line also has a new fingerprint, so it reopens too
- Real-world test: rotate the key in the existing `gapscan-test` Supabase project rather than deleting it, because the test site uses it

### Phase 4 — Monitoring + reports (Week 5)
- Celery Beat scheduled rescans (weekly free / daily paid)
- Alerts on new High/Critical + SSL/domain expiry (email, Telegram)
- PDF report (client-ready)
- Badge `GET /api/badge/{domain}.svg`
- TODO: check the detected WordPress version against the official WordPress latest-version API, through `safe_http`, and raise severity when it is outdated
- TODO: "CSP quality" check that flags `unsafe-inline`, `unsafe-eval` and wildcard sources. `headers.csp_weak` already does this at low severity for `script-src`/`default-src` and exact broad sources (`*`, `http:`, `https:`, `data:`), so extend it to other directives such as `style-src`, partial wildcards such as `*.example.com` and `https://*`, and severity based on how much each source weakens the policy

### Phase 5 — Monetize + polish (later)
- Razorpay plans, agency white-label (logo/name on PDF), Hindi/Gujarati report text, team members
- TODO: link sign-in methods, so GitHub and a magic link can share one account. Today Supabase only links them when the emails match, so a magic link to a different address creates a second account with its own domains

---

## Database (draft)
- **profiles**: id (= Supabase uid), email, name, plan, created_at
- **domains**: id, owner_id, hostname (unique per owner, not globally), verify_token, verified_at, verified_method, created_at
- **github_install_states**: id, owner_id, token_hash, expires_at, created_at (one-time, ties an install redirect to the user who started it)
- **github_installations**: id, owner_id, installation_id, account_id, account_login, suspended_at, created_at
- **domain_backends**: id, domain_id, kind (firebase_rtdb|firebase_storage|supabase), identifier, firebase_project_id, first_seen_at, last_seen_at, confirmed_at (null = never probed)
- **domain_backend_tables**: id, backend_id, name, access (readable|no_rows|refused), last_seen_at, meant_to_be_public_at (names and states only, never rows)
- **domain_firebase_projects**: id, domain_id, project_id, first_seen_at, last_seen_at (compared with repos only, never probed)
- **repo_identifiers**: id, repo_id, kind (supabase_ref|firebase_project|firebase_rtdb|firebase_bucket), value, first_seen_at, last_seen_at
- **repo_domain_links**: id, owner_id, repo_id, domain_id, state (suggested|confirmed|dismissed), origin (manual|automatic), created_at, updated_at
- **correlated_findings**: id, owner_id, domain_id, repo_id, kind (supabase_admin|firebase_admin|firebase_config), severity, confidence (confirmed|likely), identifier, first_seen_at, last_seen_at, rotated_at, rotated_by
- **correlated_finding_members**: correlated_finding_id, finding_id (the originals behind a combined finding)
- **repos**: id, owner_id, installation_id, github_repo_id, full_name, is_private, first_full_scan_at, needs_full_scan, created_at
- **github_deliveries**: delivery_id, received_at (webhook replay protection)
- **scans**: id, owner_id (nullable = anonymous), target_type (web|repo), domain_id, repo_id, before_sha, after_sha, target, mode (quick|full|backends), status (queued|running|done|failed), progress_json, result_status (complete|partial|incomplete), score, grade, grade_cap_reason, score_label, incomplete_reason, skipped_json, created_at, started_at, finished_at
- **findings**: id, scan_id, check_id, category, severity (critical|high|medium|low|info), title, evidence_masked, location, linked_finding_id, repo_id, rule_id, file_path, line, commit_sha, fingerprint, backend_identifier, identifier_basis (key_claim|same_file|only_project), created_at (first seen, for repo findings)
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
| POST | /api/domains/{id}/check-backends | auth, verified only, 5/min per IP, 10 per domain per hour. Probes confirmed backends only |
| POST | /api/domains/{id}/scan | full scan, verified only |
| POST | /api/github/install-url | auth. Returns the GitHub install link with a one-time state |
| POST | /api/github/installations/link | auth. Links an installation only if the state is the user's own and GitHub says their account owns it |
| GET | /api/repos | auth. Each repo's latest scan and finding counts, no finding details |
| POST | /api/repos/{id}/scan | auth, 5/min per IP, 10 whole-history scans per repo per hour. Owner only |
| GET | /api/repos/{id}/findings | auth, owner only. Masked findings by severity, each with how to replace the key |
| GET | /api/repo-links | auth. The owner's repo-to-site links, with both names |
| POST | /api/repo-links | auth, 30/min per IP. Links a repo to a verified domain, both the owner's |
| PATCH | /api/repo-links/{id} | auth, 30/min per IP. Confirms or dismisses a link. Confirming needs a verified domain |
| DELETE | /api/repo-links/{id} | auth, 30/min per IP. Removes a link. A pair still sharing a backend returns as a suggestion |
| GET | /api/combined-findings | auth, owner only. Combined findings, optionally for one `domain_id` or `repo_id`, with masked originals |
| POST | /api/combined-findings/{id}/rotated | auth, 30/min per IP. The owner says a leaked key was replaced. Records who and when, and drops it to info |
| POST | /api/github/webhook | verify `X-Hub-Signature-256` |
| GET | /api/dashboard | auth. Per-domain standing and trend, plus recent scans |
| GET | /api/domains/{id}/backends | auth, owner only. Backends named in the site's code |
| POST | /api/domains/{id}/backends/{backend_id}/confirm | auth, 30/min per IP. The owner says a backend is theirs, or takes that back. Verified domains only |
| POST | /api/domains/{id}/backends/{backend_id}/tables/{table_id}/public | auth, 30/min per IP. The owner marks a table as meant to be public, or takes that back |
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
- If bot protection is all that stops re-verification of a file-verified domain, a successful verification under 24 hours old can stand in, for backend checks only, and the report says so. A wrong or missing token still unverifies
- **Ownership** required for active + BaaS checks (DNS TXT for domains, GitHub App install for repos)
- **Rate limiting** (slowapi) — strict on `/api/scans/quick`
- Never store or log full secrets; mask everything
- GitHub App private key in env only; use short-lived installation tokens, don't store user tokens
- Verify webhook signatures; validate all input with Pydantic; locked-down CORS
- Scanner sends an honest User-Agent with a link to an "about our scanner" page: `GapScanBot/1.0 (+https://viivek.xyz/bot)`
- Polite scanning: at most about 2 requests a second per host, a small random delay between active checks, and the first bot-protection challenge ends the scan's requests to that site

## Pricing (draft, Phase 5)
- Free: 1 domain, 3 repos, weekly rescans
- Pro ₹299/mo: 5 domains, unlimited repos, daily rescans, alerts, PDF
- Agency ₹999/mo: 25 domains, white-label reports

## Validate early
After Phase 1: run free reports for 5 local businesses / student projects, collect feedback before building payments.
