# Changelog

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
