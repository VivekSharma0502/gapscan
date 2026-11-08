# Changelog

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
