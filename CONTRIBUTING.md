# Contributing to GapScan

Thanks for helping. Bug reports, fixes, new checks and clearer docs are all welcome.

Found a security problem? Please follow [SECURITY.md](SECURITY.md) and don't open a public issue.

## Getting set up

Follow [docs/SELF_HOSTING.md](docs/SELF_HOSTING.md). To run tests and lint, install the development requirements too:

```text
backend/.venv/Scripts/python.exe -m pip install -r backend/requirements-dev.txt
```

On macOS or Linux, the Python path is `backend/.venv/bin/python`.

## Before you open a pull request

Backend, from `backend/`:

```text
.venv/Scripts/python.exe -m pytest
.venv/Scripts/python.exe -m ruff check .
.venv/Scripts/python.exe -m ruff format --check .
```

Frontend, from `frontend/`:

```text
npm run lint
npm run build
```

After changing a model, create a migration from `backend/` and review the generated file:

```text
.venv/Scripts/python.exe -m alembic revision --autogenerate -m "describe the change"
```

## How we work

- Keep changes small and focused on one thing.
- Use conventional commit messages: `feat:`, `fix:`, `chore:`, `docs:`.
- Add a dated entry to `CHANGELOG.md` saying what changed and why, and update the docs if setup or commands changed.
- Open an issue before adding a dependency or starting something large.
- Check `PLAN.md` for scope and direction.
- Write findings and fixes in plain language. The people reading them may not be security experts.

## Security rules for every change

These aren't optional.

- Every outbound HTTP request from the backend goes through `backend/app/core/safe_http.py`. Don't call `httpx` directly anywhere else. The only exception is the repository scanner's `git clone`, which is restricted to `https://github.com/<owner>/<name>.git` with redirects off and the name taken from a GitHub API response.
- Active checks and backend probes run only on verified domains. Quick scans stay passive.
- Backend probes are read-only.
- Never store, log or print a full secret. Mask it.
- Never commit `.env` files or keys. Keep the `.env.example` files up to date. Fake keys in tests must be obviously fake.
- Validate all input with Pydantic, and verify GitHub webhook signatures.
- Every scanner check and any change to the SSRF guard needs pytest tests.
- Explain security decisions briefly in code comments.

## License

By contributing, you agree that your contributions are licensed under the [GNU AGPL v3.0](LICENSE), the same license as the project.
