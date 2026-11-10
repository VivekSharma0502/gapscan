# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately, and don't open a public issue.

Use GitHub's private reporting: [report a vulnerability](https://github.com/VivekSharma0502/gapscan/security/advisories/new).

Please include:

- What the problem is and what an attacker could do with it
- Steps to reproduce it, or a small proof of concept
- The commit or version you tested

Don't include real secrets or anyone else's data. Use masked values or test credentials.

This is a small open-source project with no paid bounty. Reports will be acknowledged as soon as possible, and you'll be credited in the fix unless you'd prefer not to be.

## In scope

- The SSRF guard (`backend/app/core/safe_http.py`) and anything that sends a request without it
- Active checks or backend probes running without verified ownership
- Reading or changing another user's data
- A full secret being stored, logged or returned
- GitHub webhook signature or installation-linking bypasses
- Authentication and authorization flaws

Out of scope: findings against a deployment you don't run, denial of service by volume, and problems that need a compromised host or an already leaked key.

If you find a problem in someone else's deployment, report it to whoever runs it. Don't test it without their permission.

## Supported versions

Only the latest commit on `main` is supported.

## Responsible use

GapScan is a security tool, so how it's used matters.

- **Scan only what you own or have written permission to test.** This applies to websites, repositories and backends.
- Unauthorized scanning can be illegal in your country, even when a tool makes it easy.
- Don't remove or weaken the SSRF guard, the domain verification, the rate limits or the polite scanning limits on a deployment other people can reach.
- Set `SCANNER_USER_AGENT` to a link of your own, so a site owner can tell who is scanning them and how to reach you.
- You are responsible for how you run your own deployment.

The software is provided without warranty, as set out in the [LICENSE](LICENSE).
