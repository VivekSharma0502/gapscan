# Changelog

## 2026-11-09: Phase 3, step 3a-2: secure GitHub installation linking

**Added**
- `POST /api/github/install-url` starts an install with a one-time state, and `POST /api/github/installations/link` finishes it and saves the account's repos. `GET /api/repos` lists them.
- A `/repositories` page with a Connect GitHub button and repo list, a `/repositories/connect` page that GitHub redirects back to, and "Repositories" in the user menu. Scanning and findings arrive in later steps.

**Security**
- An `installation_id` in a URL proves nothing, so an installation is only linked when GitHub says its account's numeric id matches the GitHub account the user signed in with. An attacker guessing ids gets the same refusal as for an id that doesn't exist.
- That GitHub identity comes from asking Supabase, not from the access token's `user_metadata`, which any user can edit about themselves.
- The state value is random, stored only as a hash, expires in 10 minutes, works once and only for the user who started the install. A failed attempt uses it up.
- A repo that moved to a new owner gets a new row, so its old findings don't come with it.
- One GitHub installation can't be attached to two GapScan accounts.

**Decisions**
- Organizations are refused for now, as agreed in the plan.
- The callback is a frontend page, because the API's sign-in is a bearer token that a browser redirect can't carry.

## 2026-11-09: Phase 3, step 3a-1: GitHub App foundations

**Added**
- A GitHub App client: signs the app's short-lived JWT, looks up who an installation belongs to, lists repos, and issues and revokes installation tokens.
- Tables for installations, repos, one-time install states and webhook deliveries, plus repo columns on `scans` and `findings`. Run `alembic upgrade head`.
- Settings for the GitHub App, and `SUPABASE_PUBLISHABLE_KEY` for the backend. "GitHub App setup" in the README covers creating the app and where each value goes.
- gitleaks is now a prerequisite for repo scanning. It's a system tool, not a Python or npm package.

**Security**
- `safe_http` can now make authenticated API calls. They are HTTPS only, get the same SSRF checks, can't override `Host` or `User-Agent`, and refuse redirects so a token can't be forwarded to another address.
- Scan tokens are limited to one repo and read-only, and tokens used to list repos can't read code.
- Repo names from GitHub must match a strict owner/name pattern, because they end up in a git URL.
- Validation errors from GitHub responses never quote the response, which could contain a token.

**Decisions**
- `git clone` can't go through `safe_http`, so it's a documented exception limited to `https://github.com` and names from the GitHub API.
- Masks are fixed per provider (`AKIA****`), because `--redact` can only keep the start of a secret and a long key would leave a lot of it on disk.
- Repo findings are deduped on a hash of gitleaks' fingerprint, so a rescan keeps the original row and its first-seen date. It's hashed because file paths can be too long for a Postgres index.

## 2026-11-09: Phase 2, step 2c: dashboard and rename to GapScan

**Added**
- A `/dashboard` page, now where sign-in lands unless the person was heading somewhere specific, and "Dashboard" in the user menu. It has a card per domain and a recent scans list, with empty states for a new account, a domain with no scans and a first scan.
- A score history chart per verified domain, where clicking a point opens that scan and a hollow point marks a partial result. Each card also has a paginated scan history list, which is the keyboard and screen reader route to the same scans.
- New dependency: `recharts`.
- `GET /api/dashboard`: each domain's latest grade and score, last scan and change from the previous scan, plus the 10 most recent scans, including claimed anonymous ones.
- `GET /api/domains/{id}/scans`: a domain's full scans, newest first, paginated, with `scored_only` for charts. Someone else's domain returns 404.
- Three indexes for these reads. The owner-only index on `scans` is replaced by one that also covers its date order. `alembic upgrade head` applies them.

**Security**
- Lists return summaries only, with no findings or evidence, and the dashboard doesn't return verification tokens.
- Full scans stay owner-only in every list, even if a claim row points at one.

**Decisions**
- Verified domains are graded from full scans only, because a quick scan runs fewer checks and mixing them would show false score changes. Unverified domains show their latest quick scan, labelled as such.
- No trend is shown when either scan is partial, because skipped checks can inflate a score.
- A scan stuck past the 5-minute limit is listed as failed without the read writing anything.

**Changed**
- The product is now GapScan. The name is set once, in `product.json`, and the backend and frontend both read it, so a future rename is a one-line change. A build or startup without the file fails rather than showing an old name.
- New domains publish `_gapscan-verify` and `gapscan-verify.txt`. Domains that existed before the rename keep accepting the `scankit-verify` names as well, tracked per domain, so nobody's verification breaks and the old names retire on their own. Run `alembic upgrade head`, and restart the worker.
- A domain only loses its verification when every accepted name has definitely failed. A temporary failure on an older record doesn't count.
- Verification names are fixed strings and don't follow `product.json`, because customers publish them. Database, Celery and browser storage names stay `scankit`, since users never see them and changing storage keys would lose unredeemed claim tokens.
- `SCANNER_USER_AGENT` now defaults to a value built from the product name. A copy of it in `.env` overrides that.

## 2026-11-08: Phase 2, step 2b: verified domains and active checks

**Added**
- A `/domains` page, linked as "My domains" in the user menu: add up to 3 domains, verify them, and run full scans. Run `alembic upgrade head`, and restart the worker so it picks up the new task.
- Two ways to prove ownership, each with its own token: a DNS TXT record at `_scankit-verify.<hostname>`, or a file at `/.well-known/scankit-verify.txt` for sites on shared platforms. A prefixed name is used because a hostname with a CNAME can't also have a TXT record.
- Verification failures say what went wrong for each method: TXT not found yet, wrong token, file missing, a web page returned instead of the file, redirected elsewhere, or site unreachable.
- Six active checks, for verified domains only: exposed `.env` files, `.git`, `.DS_Store`, backup files, public source maps and directory listings. Each one matches the file's content, so single-page apps that return their HTML for every path don't trigger false alarms.
- `POST /api/domains/{id}/scan` runs a passive and active scan. Only one can run per domain at a time, with at most 10 per domain per hour.

**Security**
- The worker proves ownership again before every full scan, because a domain can change hands after it was verified. If the proof is definitely gone the domain becomes unverified and only passive checks run. A temporary failure skips the active checks but keeps the verification.
- `safe_http` can now refuse a redirect to another host before sending it. Active probes need this to stay on the verified site, and the verification file needs it so another server can't supply the token.
- The verification file must contain only the token, so a site that shows visitors' text on every page can't be used to verify it.
- Full scan reports return 404 to anyone but their owner. Other scans still show a teaser, but even the top findings of a full scan could name an exposed file and its keys.
- Evidence is built only from fixed paths and key names, so the contents of an exposed file are never stored.

**Changed**
- A probe that got no reliable answer leaves its check skipped and the score labelled partial. Unanswered is not the same as clear.
- Signing out now clears all cached account data from the page, including domains.

## 2026-11-08: Phase 2, step 2a: Supabase Auth

**Added**
- Sign-in with GitHub or an email magic link: a `/login` page, an `/auth/callback` page and a header user menu with sign out. Supabase handles Auth only, and app data stays in local Postgres.
- The API verifies Supabase access tokens against the project's public keys. Only ES256 and RS256 are accepted, so unsigned tokens and algorithm confusion are refused, and the backend holds no Supabase secret. A legacy HS256 project is not supported and must rotate to asymmetric signing keys.
- A `profiles` table, created from the verified token on write routes so that polling a scan stays read-only.
- `POST /api/scans/claim`, which attaches anonymous scans to the signed-in user. Signing up now redeems the tokens saved in the browser and opens the full report.
- The sign-in error page names what failed: a GitHub failure says to try again, and only a magic link failure explains that links expire. The provider's own error text is logged to the console in development and never shown on the page, because anyone can craft that URL.
- New dependencies: `PyJWT[crypto]` and `@supabase/supabase-js`.
- `profiles`, `scan_claims.claimed_by` and `claimed_at`, and a foreign key on `scans.owner_id`. Run `alembic upgrade head`, and add the new values from `.env.example`.

**Changed**
- Signing keys are fetched through `safe_http`, not PyJWT's own client, so the SSRF rule has no exception. Keys are refreshed every 10 minutes, and forged key ids can't force repeated fetches.
- The full report now goes to the owner and to anyone holding a redeemed claim, because scans of one site within 10 minutes share a row and each visitor's token must still work.
- A signed-in user who gets a recently scanned site back now receives the full report. They would otherwise be stuck on the teaser for a scan they had just asked for.
- A token that fails verification returns 401 rather than being treated as anonymous, and the 503 for unreachable signing keys works the same way, so a broken session is never mistaken for a logged-out one.

## 2026-11-08: Grade caps

**Changed**
- No HTTPS, or an expired or untrusted certificate, now caps the grade at F, and any other critical finding caps it at D, because points alone let a site with a broken connection earn a passing grade. The numeric score is unchanged.
- A line under the gauge explains a cap when it changed the grade, for example "Capped at F: site doesn't offer HTTPS".
- A scan stopped by an expired or untrusted certificate now shows an F with no score. It used to show no grade at all, because the site's pages can't be read to calculate a score.

**Added**
- A `grade_cap_reason` column on `scans`. Run `alembic upgrade head`.

## 2026-11-08: Merge workflow in CLAUDE.md

**Docs**
- `CLAUDE.md` now says to merge a verified step to `main`, push and delete its branch unless told otherwise, so finished work doesn't sit on branches.

## 2026-11-08: Results summary for info-only scans

**Changed**
- When every finding is info-level, the results summary says "No issues found · 1 note" instead of counting issues, and the sign-up teaser says "notes" too. Info findings cost no points, so calling them issues overstated the problem.

**Docs**
- Added a later TODO to `PLAN.md` for a broader "CSP quality" check, building on `headers.csp_weak`.

## 2026-11-08: Phase 1, step 1d: results page

**Added**
- Results on `/scan/[id]`: a score gauge with grade and any `score_label`, or `incomplete_reason` and no gauge when the scan has no score.
- Findings grouped by severity, each with "What it means" and "How to fix" tabs. Fixes are shown per platform with copy buttons, and choosing a platform once applies to every finding.
- A sign-up teaser saying how many findings are hidden. Its button is disabled until accounts arrive in Phase 2.

**Security**
- Evidence comes from the scanned site, so it is only ever rendered as text.

## 2026-11-08: Phase 1, step 1d: live scan progress

**Added**
- `/scan/[id]` polls the scan once a second and shows each step in a terminal-style log with a progress bar. The address can be refreshed or shared at any point.
- A failed scan offers a fresh attempt, and an unknown id gets a clear message.

**Security**
- The log shows plain `done` and `running` with no ticks or color, and uses neutral step names, because an id like `tls.cert_expired` next to `done` would read as a finding.
- Scan pages ask search engines not to index them, since a report lists a site's weaknesses.

## 2026-11-08: Phase 1, step 1d: landing page

**Added**
- Landing page with a domain form that starts a quick scan, saves its claim token and opens the scan's page. It replaces the Phase 0 health check page.
- Inline messages for invalid domains, rate limits and outages, using the three error shapes the API returns.

**Security**
- The form only rejects empty input. The API alone decides what can be scanned, so the SSRF rules live in one place.

## 2026-11-08: Phase 1, step 1d: frontend foundation

**Added**
- Dark theme by default with a saved light option, applied before first paint so there is no flash.
- Severity color tokens, a typed API client and localStorage storage for scan claim tokens.
- `@tanstack/react-query` for polling, plus the shadcn card, input, tabs and badge components.

**Fixed**
- `--font-sans` referenced itself, so the Geist font was never applied.

**Security**
- Claim tokens are never logged or put in a URL. localStorage is readable by XSS, which is acceptable because a token can only claim one anonymous passive scan.

## 2026-11-08: Phase 1, step 1d: step log and finding count in the scan API

**Added**
- `progress.steps` lists every step so far with `done` or `running`, sent whole on each poll. Checks finish in milliseconds, so a page polling once a second would otherwise miss nearly all of them.
- `total_findings` gives the number of findings on a scan, so the teaser can say how many are hidden.

**Security**
- A step holds only its name and `done` or `running`, never pass/fail or severity. `done` means the check ran, so the log looks the same whether or not a check found anything. Tests enforce this, and the response model drops anything else stored with a step.

## 2026-11-08: Phase 1, step 1c: quick scan routes

**Added**
- `POST /api/scans/quick` starts a passive scan from a domain or http(s) URL.
- `GET /api/scans/{id}` returns status, progress, score and findings. Anyone but the scan's owner gets the top 3 findings. Accounts arrive in Phase 2, so today that is everyone.
- A scan still unfinished after 5 minutes reads as failed, so a dead worker can't leave the page polling forever.
- A `claim_token` for anonymous requests, so Phase 2 can attach a scan to a new account. It is returned once, by the POST only.

**Security**
- 5 scans per minute per IP, counted in Redis so the limit holds across API processes. If Redis is down the API returns 503 and starts nothing.
- A scan of the same hostname from the last 10 minutes is returned instead of starting a new one, and each hostname gets at most 20 new scans per hour across all IPs, so the scanner can't be used to flood a site. Failed scans aren't reused but do count towards the cap, since they may have sent traffic.
- A Postgres lock per hostname stops simultaneous requests from getting past both limits.
- Targets go through the SSRF guard's rules on arrival. IP addresses and single-label names are refused.
- The response uses a fixed model, so owner ids and claim data can't leak into it.

## 2026-11-08: Phase 1, step 1c: Celery scan worker

**Added**
- A Celery worker runs quick scans, saves progress for every step, and stores the report and findings in one transaction, so nobody can read a half-saved result.
- Starting a scan is one atomic update, so a redelivered task can't run it twice, and a late worker can't overwrite a scan that has already expired.

**Security**
- Celery accepts JSON only, because accepting pickle would let anyone who can write to Redis run code.
- The job carries only the scan id, and the target is read from the database.
- Progress holds counts and the step name only. Per-check results there would reveal findings hidden from anonymous viewers.
- Failures log only the error type, since the message could echo site content.

## 2026-11-08: Phase 1, step 1c: progress callbacks and passive-only gate

**Added**
- `collect_context` and `run_checks` report each step as it starts, so a worker can show live progress. Collection counts as steps too, because it takes nearly all of a scan's time.

**Security**
- Checks can be marked `active`, and `run_checks` leaves them out unless a caller opts in. No active checks exist yet, so this stops Phase 2's from running in quick scans.

## 2026-11-08: Phase 1, step 1c: Postgres, scan tables and migrations

**Added**
- Local Postgres in `docker-compose.yml`, published on loopback only like Redis.
- `scans`, `findings` and `scan_claims` tables with Alembic migrations, so scan jobs and results can outlive a request. Run `pip install -r requirements-dev.txt`, then `alembic upgrade head`.
- `scans.result_status` sits beside the job `status`, because a job can finish while the scan itself was partial or incomplete.

**Changed**
- Local service URLs use `127.0.0.1`. The containers are published on IPv4 only, and on Windows `localhost` tries IPv6 first, which stalled every new Postgres connection. Update `REDIS_URL` in your `.env` to match.

**Security**
- Scan ids are random UUIDs, because anyone holding the id can read the teaser.
- Claim tokens are stored only as hashes, one per requester, so a leaked database can't be used to claim scans and shared scans never share a token.
- Row level security is on for all three tables. Supabase publishes public tables through its REST API, and RLS with no policies closes that path.
- Alembic reads the database URL from settings, so credentials stay out of `alembic.ini`.

## 2026-11-08: Phase 1, step 1b: fairer scan outcomes

**Fixed**
- HTTP-only sites are no longer incomplete. Header, cookie and WordPress checks run on the HTTP homepage, `tls.no_https` stays critical, and the site gets a real score. HSTS and the HTTP redirect check don't apply without HTTPS, so they are left out and the same problem isn't charged twice.
- A homepage returning 403, 429 or 503 stays incomplete, with a reason saying bot protection or a firewall blocked the scan. Other 4xx responses such as 401 and 404 come from the real app, so checks now run on them. Other 5xx responses stay incomplete with a generic reason.
- `tls.no_https` is no longer reported when HTTP redirects to a secure host, for example when only `www` has a certificate.

**Added**
- A `partial` scan status with a `score_label` such as "Partial — 3 checks skipped", for scans where a DNS or TLS lookup failed, so a possibly generous grade is labelled. Checks skipped by design, such as SPF on `*.vercel.app`, don't count.

## 2026-11-08: Phase 1, step 1b: collector and scan report

**Added**
- `collect_context` gathers TLS, homepage, HTTP and DNS data through `safe_http`. One failed input doesn't stop the scan.
- `run_checks` builds the report: findings sorted by severity, score, grade, and a list of skipped checks with reasons.
- If the homepage can't be fetched over HTTPS, the scan is marked `incomplete` with a clear reason and gets no score or grade, because a partial score would flatter a broken site. Findings that did run are still shown.

**Changed**
- `PLAN.md` file list now includes `cookies.py`.

**Security**
- A blocked target stops the collector immediately, so it gets no further requests or lookups.
- A check that crashes on odd input is reported as skipped, and only the error type is logged, since the message could echo the site's content.

## 2026-11-08: Phase 1, step 1b: WordPress version check

**Added**
- A check that reports the WordPress version shown in the homepage generator tag. It only reads the homepage already fetched, so it stays passive.
- A TODO in `PLAN.md` (Phase 4) to compare the version against the official latest-version API, because a hardcoded "latest" would go stale.

## 2026-11-08: Phase 1, step 1b: DNS and email checks

**Added**
- Checks for missing or weak SPF and DMARC and missing CAA, with text and DNS fixes per platform.
- An info note for hosts on shared platform domains such as `*.vercel.app`, explaining why SPF, DMARC and CAA don't apply. Those records belong to the platform, so owners aren't marked down for them.

**Changed**
- Added `publicsuffixlist`, which ships the list offline and makes no network calls. It finds the real registered domain for names like `shop.example.co.in` and identifies shared platform domains. Run `pip install -r requirements-dev.txt` to pick it up.

## 2026-11-08: Phase 1, step 1b: cookie checks

**Added**
- Checks for the `Secure`, `HttpOnly` and `SameSite` flags, with text and platform fixes. Each check gives one finding listing the affected cookies, so many cookies don't multiply the deduction.
- `HttpOnly` is only required on session-like cookies, because anti-CSRF and preference cookies are often meant to be read by scripts.

**Security**
- Only cookie names reach findings. Values can be session tokens, so they are dropped as soon as a header is parsed.

## 2026-11-08: Phase 1, step 1b: security header checks

**Added**
- Checks for missing or permissive CSP, clickjacking protection, X-Content-Type-Options, Referrer-Policy, Permissions-Policy and server version leaks, using MDN Observatory's rules as the reference, with text and platform fixes.
- CSP checks follow browser behaviour, so a nonce or hash cancels `'unsafe-inline'`, and Report-Only does not count as a policy.

## 2026-11-08: Phase 1, step 1b: TLS checks

**Added**
- Checks for missing HTTPS, expired, untrusted and soon-to-expire certificates, TLS 1.0/1.1, missing HTTP to HTTPS redirect, and missing or short HSTS, each with plain-language text and fixes for Vercel, Netlify, nginx and Cloudflare.
- `SkipCheck`, so a check that can't get a reliable answer is reported as skipped, not passed.

## 2026-11-08: Phase 1, step 1b: TLS probe and DNS records in the SSRF guard

**Added**
- `safe_tls_probe` reads certificate status, expiry, negotiated protocol and whether TLS 1.0/1.1 is accepted, using handshakes only, so it stays passive. Certificate details come from Python's `ssl`, so no new dependency was needed.
- `safe_dns_records` reads TXT and CAA records through the same fallback chain as address lookups, because the development network blocks UDP DNS.

**Security**
- The probe uses the same URL, DNS and IP checks as HTTP requests, pins the validated IP, and only connects to port 443.
- A timeout or dropped connection raises instead of reporting a problem, so an unknown result can't be mistaken for "no HTTPS".
- The guard test now also fails if other app code imports `socket`, `ssl` or `dns`.

## 2026-11-08: Phase 1, step 1b: check registry and scoring

**Added**
- `app/checks/`: `Finding`, `ScanContext`, a `@check` registry and a text catalog keyed by `check_id`. Checks are pure functions of the context, so they can be tested with fixtures and cannot bypass the SSRF guard.
- A check with no text, or a fix missing a platform, fails at import, so a finding can never ship blank.
- Score and grade from `PLAN.md`.

**Security**
- Evidence is stripped of control characters and capped in length, because it is copied from responses the scanned site controls.

## 2026-11-08: DNS fallback chain for networks that block UDP

**Added**
- `safe_http` now resolves through a chain: configured (or system) DNS servers over UDP, the same servers over TCP, DNS-over-HTTPS (Cloudflare, then Google), then the operating system. The development network blocks UDP port 53, so every lookup was failing.
- `SCANNER_DNS_TIMEOUT_SECONDS` (default 5), applied to each resolver and bounded by the request's total deadline.

**Security**
- Only failures move to the next resolver, and answers are never merged across resolvers, so a partial answer cannot hide a private record.
- Addresses from every resolver still go through the same IP checks, and a private answer blocks the request.
- DoH endpoints are hardcoded IP literals with verified certificates, so they do not depend on the DNS that just failed. Hostnames being scanned are only sent to them when the earlier resolvers fail.

## 2026-11-08: Configurable DNS servers for scans

**Added**
- Optional `SCANNER_DNS_SERVERS` setting (comma-separated IPs, validated at startup). Empty keeps the system's DNS. Windows machines can list dead DNS servers from disconnected adapters, which used up the lookup timeout before a working server was tried, and public resolvers also keep scans away from internal DNS views.

## 2026-11-08: Phase 1, step 1a: SSRF-safe HTTP client

**Added**
- `backend/app/core/safe_http.py`, the only allowed path for outbound HTTP, because scans fetch URLs chosen by anonymous users and must never reach internal services or cloud metadata.
- URL checks (http/https, ports 80/443, no credentials, no numeric host tricks) and IP checks covering private, loopback, link-local, CGNAT, reserved, multicast, IPv6 ULA and link-local, IPv4-mapped, NAT64 and tunnelling ranges.
- Connections go to the validated IP with the real hostname kept for `Host`, SNI and certificate checks, which prevents DNS rebinding.
- Manual redirects (max 5) with full re-validation on every hop, connect/read timeouts, a 20s total deadline, and a 2 MB cap on decompressed bodies. Larger responses return the first 2 MB with `truncated=True`, so header checks still work on big pages.
- `SCANNER_USER_AGENT` setting so scan traffic identifies itself.
- pytest coverage for the guard, plus a test that fails if any other app module imports `httpx`.

**Changed**
- `httpx` moved from dev to runtime requirements, and `dnspython` added so DNS lookups have a real timeout.

## 2026-11-08: Phase 0 scaffold

**Added**
- Monorepo with `frontend/` (Next.js App Router, TypeScript, Tailwind, shadcn/ui) and `backend/` (FastAPI, SQLModel), so later phases have a working base.
- `GET /api/health` and a home page that calls it and shows the status, to prove the frontend and backend talk to each other end to end.
- `docker-compose.yml` with Redis published on loopback only, because it runs without auth locally.
- CORS allowlist read from the env, so only the configured frontend origins can call the API from a browser.
- pytest tests for the health route and CORS, plus ruff for backend lint.
- `.env.example`, `.gitignore`, `README.md` and this changelog.
