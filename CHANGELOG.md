# Changelog

## 2026-11-11: Precise DMARC and SPF grading

**Changed**
- DMARC `p=none` is now its own finding, "monitoring only: spoofed mail is still delivered", and costs 7 points (MEDIUM), the same as having no DMARC record. It used to cost 2. The fix text calls it a good first step and explains how to move to quarantine.
- `p=quarantine` is a pass with a free note that `p=reject` is stronger. `p=reject` is a plain pass.
- New DMARC findings, 2 points each: `pct` below 100 or `t=y` on a strict policy, and `sp=none` when the main policy is strict.
- DMARC follows RFC 7489 more closely. Several DMARC records, or a record with no valid `p` and no `rua`, count as no DMARC. A record with no valid `p` but with `rua` counts as `p=none`.
- SPF `+all` (or a bare `all`) is now its own HIGH finding (15 points), because forged mail then passes SPF and can satisfy DMARC too.
- SPF `?all`, or a record with no `all` and no `redirect=`, stays a MEDIUM finding. Several SPF records are now their own MEDIUM finding with a merge fix.
- SPF `~all` gets a free note explaining soft fail versus `-all`. `-all` is a plain pass.
- The `dns.dmarc_weak` check is replaced by the new checks. Old scans keep their stored findings.

**Why**
- A reader asked whether the grade tells monitoring-only DMARC apart from enforcement. It did, but `p=none` cost only 2 points and kept an A+, and `+all` cost the same as `?all`.

## 2026-11-10: Preparing the repo for open source

**Changed**
- The remaining ScanKit names are now GapScan: the Celery app, browser storage keys, and the local Postgres user, password and database. Browser storage resets once, so the theme choice and any unclaimed scans are lost.
- An existing local database keeps its old name, because Postgres only reads those settings on first start. To keep it, set `DATABASE_URL` in `.env` to the old `scankit` values.
- The scanner's default User-Agent now links to the public repository. Anyone self-hosting should set `SCANNER_USER_AGENT` to a page of their own.
- `.env.example` now covers every backend setting, and the frontend's settings moved to a new `frontend/.env.example`.
- The README now describes the project for new visitors: features, stack, architecture, security design and a quick start. Detailed setup moved to `docs/SELF_HOSTING.md`.
- Added `docs/SELF_HOSTING.md`, a step-by-step guide for Windows, macOS and Linux with troubleshooting.
- Added `SECURITY.md` for reporting vulnerabilities and responsible use, and `CONTRIBUTING.md`.
- The project is licensed under the GNU AGPL v3.0.
- The README now shows real screenshots, stored in `docs/screenshots/`, in place of the placeholders.

**Decisions**
- The `scankit-verify` DNS and file names stay accepted, because removing them would unverify domains set up that way.

## 2026-11-10: Rotated card wording on reports

**Fixed**
- A card marked as rotated now says "This scan didn't count it against your score" on a full report from a scan started after the rotation. The repository page and reports older than the rotation still say it stops affecting the score from the next full scan. Restart the API.

**Decisions**
- A scan already running when the key was marked as rotated keeps the future wording, because it may have read the key while it still counted.

## 2026-11-10: Combined card wording on reports, and a rotate/reopen test

**Fixed**
- A combined card on a report whose score already included the leak now says "This scan deducted 25 points", not "Your next full scan deducts". The repository page and reports with no deduction keep the old wording.

**Added**
- A test for the full rotate, reopen, rotate, full scan sequence.

**Security**
- A scan id belonging to someone else is treated as no scan id, so it can't be used to probe scans.

## 2026-11-10: Fix: "Yes, link them" failed in the browser

**Fixed**
- `PATCH` was missing from the CORS allowed methods, so the browser's preflight got a 400 and answering a repo link suggestion never reached the API. Restart the API.
- An unhandled server error now returns a JSON 500 with CORS headers, so the page shows it instead of "couldn't reach the scanner".
- When a request is blocked but the API is up, the page now says so. Browsers hide the status of a refused preflight, so the page checks `/api/health` to tell this apart from a dropped connection.

**Security**
- CORS still allows only the methods and headers our routes use, and `allow_origins` is unchanged. Details of a 500 stay in the server log.

## 2026-11-10: Phase 3, step 3c-7: leaked repo keys in the site score

**Added**
- A confirmed leak of a Supabase admin key or Firebase service account, for a backend a site uses, now costs 25 points and caps the grade at D from the next full scan. The report explains what was counted. Run `alembic upgrade head` and restart the API and worker.

**Security**
- A leaked key is never counted twice. It counts once per project however many commits, keys or repositories are involved, and adds nothing if the same scan already found that key on the site, or found a site key it can't tie to a project.
- Combined findings aren't in the findings table, so the scorer can't sum them. They reach the score only through one explicit list.

**Decisions**
- Likely matches, keys marked as rotated, and Firebase config matches never affect the score. Quick scans are never affected.
- Saved scans are never rewritten. A new leak changes the score from the next full scan, and the card appears straight away.

## 2026-11-10: Phase 3, step 3c: reopening a key marked as rotated

**Added**
- A "Reopen this finding" option on a card marked as rotated. It restores the finding and records who reopened it and when. Run `alembic upgrade head` and restart the API.

**Decisions**
- If a new card is already open for that project, the two merge, so a project never has two open cards.
- A card whose repo and site no longer match stays rotated instead of reopening, because an open card with no match would be removed by the next refresh.

## 2026-11-10: Phase 3, step 3c-6: the combined finding card

**Added**
- Combined findings now appear above the originals on full scan reports and on a repository's findings page. Each has steps to replace the key, steps to clean up git history, and the original findings, which stay viewable. Restart the API.
- An "I've rotated this key" option. It records who marked it and when, shows "Owner marked as rotated", drops the finding to info and keeps the history reminder. A repo finding that rotation didn't cover raises a new card.

**Security**
- Combined findings are owner only, with only masked evidence. They never appear on quick or anonymous reports, because only a full report given to its owner names a domain.
- A rotation is recorded as the owner's word, because checking it would mean holding the key or contacting the provider.

**Decisions**
- Steps were checked against the current Supabase, Firebase, Google Cloud and GitHub documentation, and each links to its source. Cleaning history comes after replacing the key, because GitHub says a replaced key may not need a rewrite at all.

## 2026-11-10: Phase 3, step 3c-5: linking repos to websites

**Added**
- A section on the Repositories page shows suggested links between repositories and verified websites. You can accept them, mark them as not related, undo that, or link a pair yourself.
- `/api/repo-links` routes for listing, creating, answering and removing links. Each change rebuilds the combined findings straight away.

**Security**
- Every route checks the signed-in user owns both the repo and the domain, and answers 404 otherwise, so ids can't be probed.
- Only a verified domain can be linked or confirmed. Marking a pair as not related is always allowed.
- A link never makes a finding on its own. It can only tie a key with no known project to the site's only Supabase project, and only as "likely".

## 2026-11-10: Phase 3, step 3c-4: correlation logic and link suggestions

**Added**
- After each repo scan, full scan and backend check, GapScan rebuilds that owner's combined findings and repo-to-site link suggestions from stored data. The screens come in later steps, so nothing visible changes yet. Run `alembic upgrade head` and restart the worker.
- A leaked Supabase admin key, or a Firebase service account, for a project a verified site uses makes one critical combined finding. It's marked "likely" when the project was only inferred. A Firebase config that matches makes one info finding.
- Full scans now save the Firebase `projectId` from the config itself, in `domain_firebase_projects`, so a site whose config names no database or bucket can still match a repo.

**Security**
- Correlation reads and writes the database only, and a test fails if it tries to reach the network or run a program.
- Matching stays inside one owner's repos and verified domains. A domain that loses verification loses its open combined findings.
- Project IDs have their own table so they can never be confirmed or probed like a backend.

**Decisions**
- Originals are never changed. A combined finding only points at them, along with the site's service-key finding from the latest full scan.
- A key marked as rotated stays as history. A repo finding that rotation didn't cover opens a new combined finding.
- A dismissed link hides the combined finding. A confirmed link can tie a key with no project to the site's only Supabase project, but only as "likely".

## 2026-11-10: Phase 3, step 3c-3: project identifiers from site scans

**Added**
- Full scans now keep the Firebase project ID next to each Firebase database and bucket they find.
- A Supabase server-only key found on a site is tied to its project: from the key's `ref` claim, from a Supabase URL in the same script, or from the only Supabase project the site names. If the site's keys point at more than one project, the finding names none. Restart the worker, then run a full scan to fill these in.
- A test that a Supabase key found only in git history is tied to the project in its own commit, not the latest code.

**Security**
- These come from text the site controls, so a Firebase project ID of the wrong shape is dropped. Only identifiers are saved, never any part of a key.

## 2026-11-10: Phase 3, step 3c-2: project identifiers from repo scans

**Added**
- Repo scans now record which Supabase projects and Firebase projects, databases and buckets a repo points at, in `repo_identifiers`. Restart the worker, then run **Scan now** on a repo to fill these in for findings it already has.
- A Supabase admin key found in a repo is tied to its project: from the key's `ref` claim, from a Supabase URL in the same file, or, labelled as a guess, because the repo names only one project. A Firebase service account file is tied to its `project_id`.

**Security**
- This runs on the temporary clone the scan already has, after the GitHub token is revoked, so it makes no new outbound requests.
- Only identifiers are kept. File text is searched and let go, `git grep -o` returns only the short match, and each value must fit the exact shape of an official identifier.
- A failure here costs only the link between repo and site. It never fails the scan, and it leaves the identifiers already saved in place.

## 2026-11-10: Phase 3, step 3c-1: correlation tables

**Added**
- Tables for connecting repos to sites: `repo_identifiers`, `repo_domain_links`, `correlated_findings` and `correlated_finding_members`. `findings` gains `backend_identifier` and `identifier_basis`, and `domain_backends` gains `firebase_project_id`. Nothing uses them yet, so behaviour is unchanged. Run `alembic upgrade head`.

**Security**
- These tables hold project identifiers and states only. Nothing has a column for a key.
- Combined findings live apart from `findings`, so the scorer can't count them by accident.

**Decisions**
- Originals link to a combined finding through a separate table instead of a column on `findings`. One key can sit behind cards for two sites, and these rows also record which fingerprints a rotation covered.
- Only one card can be open per domain, repo, kind and project. A card marked as rotated stays as history, so a key found later opens a new one.

## 2026-11-10: Phase 3, step 3b fix: backend card wording

**Fixed**
- The "Backends found in your website's code" card said GapScan hadn't tested a backend even after its owner confirmed it and the probes ran. That text now appears only for unconfirmed backends.
- Confirmed backends that answered get a new "Your backends were tested read-only" card pointing to the "Checked:" results. Confirmed backends with no reliable answer get their own card, because calling them tested would be untrue.
- Report text is looked up by check id, so these are separate checks. Reports from before this fix keep the old card until the site is scanned again. Restart the worker to pick this up.

## 2026-11-10: Phase 3, step 3b: Supabase probes

**Added**
- `baas.supabase_table_readable` (high): a table named by `.from()` in the site's scripts returned rows to its public key. Comes with an "enable RLS and add a policy" SQL snippet. Run `alembic upgrade head`, and restart the worker.
- A "This table is meant to be public" option per table on My domains. A marked table becomes info and stops affecting the grade from the next full scan.
- An explicit "Checked: tables returned no rows to the public" result, which says an empty table looks the same as a protected one.

**Security**
- HEAD requests only, so no row ever leaves Supabase. Only table names and their state are stored.
- Only the anon or publishable key from the site's own code is sent, held in memory for that scan and never stored. A service_role or secret key found in a bundle is never used.
- An anon key must name the same project as the URL. A publishable key names none, so it's only used when the site has exactly one project.

**Decisions**
- Supabase no longer lists tables to public keys, so names come from the site's scripts. Tables the scripts don't name aren't checked, and `Array.from` and `storage.from` calls are ignored.
- Supabase probes need the key from the site's code, so they run in full scans. "Check backends" still covers Firebase only.

## 2026-11-10: Phase 3, step 3b: Check backends

**Added**
- A "Check backends" button on My domains runs only the probes for confirmed backends, and `POST /api/domains/{id}/check-backends` starts it. Apart from re-proving ownership it sends nothing to the website, so a site behind bot protection can still have its backends checked. It has no score and is owner-only. Run `alembic upgrade head`, and restart the worker.
- Explicit results when a backend refuses: "Checked: database not publicly readable" and "Checked: storage files can't be listed publicly". They say what wasn't covered, since only the top level of a database is tested.

**Changed**
- A successful ownership proof during a scan now updates `verified_at`. Before, only the Verify button did, so it could be days out of date.

**Security**
- If bot protection is all that stops re-verification of a file-verified domain, a verification under 24 hours old can stand in, for backend checks only, and the report says so clearly. Older than that, the check doesn't run.
- A wrong or missing token still unverifies the domain as before. A domain proven by DNS can't use this at all, because a blocked file says nothing about its DNS record.

## 2026-11-10: Polite scanning

**Changed**
- At most about 2 requests a second to any one host, enforced in `safe_http` so every request and redirect counts, along with TLS handshakes. Restart the worker to pick this up.
- Active checks (sensitive paths, scripts and backend probes) wait 0.5 to 0.9 seconds, at random, before each request. A full scan takes up to about 30 seconds longer.
- The User-Agent is now `GapScanBot/1.0 (+https://viivek.xyz/bot)`.

**Fixed**
- The first bot-protection challenge now ends the scan's requests to that site. Before, a challenge only stopped the step it happened in, so later steps still sent requests. A challenge on the verification file ends the scan straight away, and it finishes as incomplete.

**Why**
- Vercel's DDoS Mitigation challenged the scanner 17 times because its requests arrived as a burst.

**Decisions**
- The limit is per worker process. Only one full scan of a domain runs at a time, so this is enough for now.

## 2026-11-10: Phase 3, step 3b: name the platform blocking a scan

**Changed**
- Reports now name the platform when its bot protection stops a scan, from the `x-vercel-mitigated` or `cf-mitigated` header, and link to that platform's instructions for allowing GapScanBot. Run `alembic upgrade head`, and restart the worker.
- When bot protection blocks the verification file, the report says that instead of "We couldn't re-confirm that you own this domain", and adds that the domain is still verified. Verifying from My domains shows the same reason.

**Tests**
- Firebase checks are covered end to end with fixtures, from a site's script through confirmation to the finding.

## 2026-11-10: Phase 3, step 3b fix: bot protection and skipped scripts

**Fixed**
- A real site on Vercel reported "Read 0 of 1 scripts". The script's request got Vercel's Security Checkpoint (403, `x-vercel-mitigated`), and any non-200 answer was dropped without a reason. Parsing wasn't at fault: the same script finds both Firebase backends when read directly.
- Scripts are now read before the requests for sensitive paths, because that burst can set off bot protection and block ordinary requests too.
- A Vercel challenge no longer counts as a real answer for the exposure checks, matching what Cloudflare challenges already did. Those checks could previously pass on a challenge page, so a scan could read as complete when it wasn't. Affected checks now show as skipped.
- A challenged homepage no longer reads as "nothing found".

**Added**
- Findings now say why each script wasn't fully read, such as bot protection, too large, HTTP 404 or a script limit.
- `baas.scripts_unread` has its own explanation for when nothing was found but not every script was read. `baas.backends_found` now only appears when backends were found.
- Regression tests with a fixture matching this site: CDN scripts on other hosts, one relative script holding the config, and a checkpoint response. Inline `<script>` blocks are covered too.

**Security**
- Once bot protection challenges a scan, the scanner stops sending requests to that site. It doesn't try to get past it, since that's the owner's choice. The report explains how an owner can allow scans with a firewall rule.

## 2026-11-10: Phase 3, step 3b-3: Firebase probes

**Added**
- `baas.firebase_rtdb_public` (critical): the database root can be read without signing in. Stores yes/no and the number of top-level keys.
- `baas.firebase_storage_listable` (high): a bucket's files can be listed without signing in. Stores yes/no.
- Both come with per-user rule snippets from Firebase's docs. Restart the worker to pick them up.

**Security**
- Only GET requests, through the SSRF guard, to official hosts, and redirects can't leave that host. Each name is validated again when it's read back from the database.
- A backend is probed only if its owner confirmed it and this scan found it on the site.
- RTDB uses `shallow=true`, so stored values are never returned, and key names are counted and discarded. Storage asks for at most one file and doesn't read its name.
- A response is reduced to a yes/no and a count as soon as it arrives, so data can't reach a finding, the database or a log. Results have no field that could hold it.
- A backend that gave no reliable answer leaves the check skipped, not clear.

**Docs**
- `PLAN.md` has a TODO for linking sign-in methods on one account.

## 2026-11-10: Phase 3, step 3b-2: backend confirmation screen

**Added**
- Verified domains on the My domains page now list the Firebase and Supabase backends a full scan found, each with "This is mine" and "Not mine". The section is hidden until a scan has found something.

**Security**
- The screen asks people to confirm only what they own or may test, because a site's code can name someone else's service.

## 2026-11-10: Phase 3, step 3b-1: BaaS discovery

**Added**
- Full scans of verified domains read the homepage and up to 20 of the site's own scripts (1 MB each, 6 MB in total, 30 seconds) to find Firebase databases and storage buckets and Supabase projects. Results are stored per domain. Run `alembic upgrade head`, and restart the worker.
- `baas.supabase_service_key`: a `service_role` or `sb_secret_` key in code sent to browsers is critical. An info finding lists the backends found and how many scripts were read.
- `GET /api/domains/{id}/backends` and `POST /api/domains/{id}/backends/{backend_id}/confirm`, so an owner can say which backends are theirs. The screen for this arrives in a later step.
- Fixes can now be a single set of instructions in a provider's console, instead of one tab per hosting platform.

**Security**
- This step sends nothing to Firebase or Supabase. Discovery only requests the verified site, after ownership is proven again.
- A backend starts unconfirmed, and later probes will only contact confirmed ones. Owning a site doesn't prove owning everything its code names: it could be a vendor's project, or someone else's named on purpose.
- Backend names must match the exact shape of an official host or bucket, so a crafted page can't point later requests anywhere else.
- Keys are never kept. A finding holds a fixed mask and the script's path, and the token's role is read without trusting it.
- A script that couldn't be read leaves the key check skipped rather than clear.

**Decisions**
- Severity agreed for step 3b: a readable RTDB root and a service key in a bundle are critical, and a readable Supabase table is high, with a per-table "meant to be public" option that makes it info and stops it affecting the grade.
- Supabase stopped serving its table list to anon keys in April 2026, so table names will come from `.from()` calls in the site's scripts.

## 2026-11-10: Phase 3, step 3a complete

GitHub repo secret scanning is finished and verified end to end: installing the app, linking it to the signed-in account, a real push through the signed webhook and worker, and the Repositories and findings pages in the browser.

**Docs**
- `PLAN.md` marks step 3a done and lists what's left in Phase 3 (BaaS checks and correlation).
- The README has a Repo scanning section covering how to use it, the caps, what to check when a webhook returns 401, and how to set up a production GitHub App.

**Known limits**
- Personal accounts only. Organization installs need GitHub's user authorization during install.
- A finding can't be marked as rotated yet, so it stays listed until a complete whole-history scan no longer finds it.
- The worker has no Docker image yet. Production needs `git` and `gitleaks` installed on it.

## 2026-11-09: Phase 3, step 3a-6: Repositories page and dashboard section

**Added**
- `/repositories` now shows each repo's last scan and finding counts by severity, with Scan now and View findings. Scan status updates by itself while a scan runs.
- A `/repositories/{id}` page: findings grouped by severity with file, line, commit, masked value and first-found date, a "How to replace it" tab with links to the provider's page and official instructions, and the warning that deleting a file doesn't remove a secret from history.
- A Repositories section on the dashboard, most urgent first, with a Connect GitHub prompt when empty.
- `GET /api/repos` now includes each repo's latest scan and counts.

**Security**
- The repo list returns numbers only, with no files or masked values.
- "No secrets found" only appears after a finished, complete scan, so a scan that hit a limit or failed can't look like a clean result.
- Paths from scanned repos are rendered as text, and links out send no referrer, so a provider's site doesn't learn the repo page's address.

## 2026-11-09: Phase 3, step 3a-5: rotation guides checked against official docs

**Changed**
- Every provider's guide now links its official instructions (`docs_url`), and all six were checked against those docs.
- AWS: exact console steps, the limit of two keys per user, and a recommendation to move to temporary credentials.
- Google: uses the Rotate key flow, and warns that Gemini API keys look like Firebase web keys but must stay secret.
- GitHub: exact navigation, fine-grained tokens as the replacement, and a note that GitHub auto-revokes tokens pushed to public repositories.
- OpenAI: revokes rather than deletes, recommends project service accounts and expiry dates, and replaces "monthly budget" with spend alerts and hard limits.

**Security**
- New `gcp-api-key` findings are medium instead of low, because once the value isn't kept a secret Gemini key can't be told apart from a public Firebase key. Findings already stored keep their severity.

## 2026-11-09: Phase 3, step 3a-5: plain-language findings and rotation guides

**Added**
- "How to replace this key" guides for AWS, Firebase/Google, Supabase, Stripe, GitHub, OpenAI and anything else, in code and keyed by `check_id` like the website checks. Each one puts the new key live before removing the old one, so an app stays up. GitHub tokens are the exception: delete first, because a new one takes moments to create.
- Notes for cases a provider's guide can't cover. Firebase web keys and Supabase anon keys are public by design, `sk_test_` Stripe keys are much less urgent, and name-based matches may be placeholders.
- `GET /api/repos/{id}/findings`: masked findings, most serious first, with first-seen dates, counts by severity and the latest scan. The page arrives in the next step.
- Every repo's findings come with a warning that deleting a file doesn't remove a secret from git history, so the key must be replaced first.

**Security**
- Findings are owner only, and another user's repo returns 404. The response is a fixed list of fields, so the stored fingerprint isn't sent.

**Decisions**
- Advice is worded conditionally ("if this key starts with sk_test_"), because the real value is never kept and GapScan can't check which case it is.

## 2026-11-09: Phase 3, step 3a-4: gitleaks repo scanner

**Added**
- Repo scans with gitleaks over a full clone: the whole history on a repo's first scan and on `POST /api/repos/{id}/scan`, only the new commits on a push. Run the worker with `-Q celery,repo_scans`, or repo scans stay queued.
- Pushes now start scans. A new branch scans only what isn't on the default branch. A force-push, or a commit that can't be found, scans everything.
- Findings are deduped per repo on gitleaks' fingerprint, so a rescan keeps the original row and its first-seen date. A complete whole-history scan removes findings that have been rewritten out of history.
- Caps: 500 MB reported size, 1 GB on disk during the clone, 3 minutes to clone, 5 minutes to scan, 5 MB per file, 1,000 findings (most serious first). Hitting one finishes the scan as incomplete, with a reason.
- Our own gitleaks rules for Supabase secret and service role keys, which gitleaks doesn't cover.

**Security**
- git runs with `GIT_TERMINAL_PROMPT=0`, HTTPS as the only protocol (`protocol.file.allow=never`), hooks pointed at the null device, no credential helpers, redirects off, and no system or user git config. The clone is bare with an empty template, so nothing from the repo is written out as files.
- The URL is always `https://github.com/<name>.git`, with the name freshly returned by the GitHub API for the repo's numeric id.
- The token covers one repo, read-only, travels by environment variable rather than arguments or the URL, is scoped to github.com, and is revoked as soon as the clone ends. git and gitleaks get a minimal environment, so they can't see the worker's own secrets.
- `--redact=100` and a pinned `--config`, so a repo can't switch off its own rules. A report containing anything other than `REDACTED` as a secret is refused whole. Only rule, file, line, commit and fingerprint are read from it, so author names, emails and commit messages never reach the database.
- Tool output is discarded rather than captured. The temp folder is removed in `finally`, including on Windows, and a sweep at worker start clears anything left by a crash.
- Repo scans are owner-only, and push scans are capped at 30 per repo per hour. Past the cap, or if the queue is down, the next scan covers the whole history so nothing is missed.

**Changed**
- Repo scans get a 15-minute stale limit and their own queue and task time limit. The dashboard's recent scans list shows websites only.

## 2026-11-09: Phase 3, step 3a-3: GitHub webhook

**Added**
- `POST /api/github/webhook` handles `installation`, `installation_repositories` and `push`. Other events are acknowledged and ignored.
- Uninstalling the app removes its repos and their findings. Suspending and unsuspending are recorded. Repos added or removed on GitHub show up in the list.
- A push now works out which commits need scanning: only the new ones normally, the whole history for a repo's first scan, a force-push or a missed push. Starting that scan arrives with the scanner in the next step.

**Security**
- Every request's `X-Hub-Signature-256` is checked in constant time against the raw bytes, before anything is parsed. With no secret configured, every request is refused, because an empty secret would let anyone sign.
- The body is capped at 10 MB while being read, so unsigned requests can't exhaust memory.
- `X-GitHub-Delivery` is recorded in the same transaction as the changes it made, so a replayed delivery does nothing, while one that failed can still be resent.
- A webhook can't link an installation to a user. Only the signed-in flow can.
- Only declared payload fields are read, so author names and emails are dropped on arrival. Commit ids must be exactly 40 hex characters, because they will be passed to git.

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
