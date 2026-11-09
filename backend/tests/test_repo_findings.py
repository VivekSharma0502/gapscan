"""Rotation guides, and the route that serves a repo's findings with them."""

import json
from collections.abc import Iterator
from datetime import timedelta
from typing import Any
from urllib.parse import urlparse
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlmodel import Session

from app.checks.base import Category, Severity
from app.core.auth import Viewer, get_viewer
from app.main import app
from app.models.github import GithubInstallation, Repo
from app.models.profile import Profile
from app.models.scan import FindingRecord, Scan, ScanJobStatus, ScanMode, TargetType, utc_now
from app.repos.guides import GUIDES, HISTORY_WARNING, RULE_NOTES
from app.repos.rules import _RULES, Provider, rule_for

# --- the guides ---


@pytest.mark.parametrize("provider", list(Provider))
def test_every_provider_has_a_complete_guide(provider: Provider) -> None:
    guide = GUIDES[f"secrets.{provider.value}"]

    assert guide.provider is provider
    assert guide.provider_name
    assert guide.what_it_means
    assert len(guide.rotate_steps) >= 3


@pytest.mark.parametrize("rule_id", sorted(_RULES))
def test_every_rule_leads_to_a_guide(rule_id: str) -> None:
    assert f"secrets.{rule_for(rule_id).provider.value}" in GUIDES


def test_unknown_rule_still_leads_to_a_guide() -> None:
    assert f"secrets.{rule_for('some-new-service').provider.value}" in GUIDES


@pytest.mark.parametrize("rule_id", sorted(RULE_NOTES))
def test_notes_are_for_rules_that_exist(rule_id: str) -> None:
    assert rule_id in _RULES


@pytest.mark.parametrize("guide", GUIDES.values(), ids=lambda guide: guide.provider.value)
def test_links_are_https(guide: Any) -> None:
    for url in (guide.rotate_url, guide.docs_url):
        assert url is None or url.startswith("https://")


@pytest.mark.parametrize(
    ("provider", "host"),
    [
        (Provider.AWS, "docs.aws.amazon.com"),
        (Provider.FIREBASE, "firebase.google.com"),
        (Provider.SUPABASE, "supabase.com"),
        (Provider.STRIPE, "docs.stripe.com"),
        (Provider.GITHUB, "docs.github.com"),
        (Provider.OPENAI, "developers.openai.com"),
    ],
    ids=lambda item: getattr(item, "value", item),
)
def test_each_provider_links_its_official_docs(provider: Provider, host: str) -> None:
    assert urlparse(GUIDES[f"secrets.{provider.value}"].docs_url).hostname == host


def _position(steps: tuple[str, ...], word: str) -> int:
    return next(index for index, step in enumerate(steps) if word in step.lower())


@pytest.mark.parametrize(
    ("provider", "removal"),
    [
        (Provider.AWS, "deactivate"),
        (Provider.FIREBASE, "delete the previous"),
        (Provider.OPENAI, "revoke"),
        (Provider.GENERIC, "delete"),
    ],
    ids=lambda item: getattr(item, "value", item),
)
def test_new_key_goes_live_before_the_old_one_is_removed(provider: Provider, removal: str) -> None:
    steps = GUIDES[f"secrets.{provider.value}"].rotate_steps

    assert _position(steps, "redeploy") < _position(steps, removal)


def test_firebase_guide_warns_that_gemini_keys_are_secret() -> None:
    assert "Gemini" in GUIDES["secrets.firebase"].what_it_means
    assert "Gemini" in RULE_NOTES["gcp-api-key"]


def test_history_warning_says_to_rotate_first() -> None:
    text = HISTORY_WARNING.lower()

    assert "doesn't remove" in text
    assert "history" in text
    assert "first" in text


@pytest.mark.parametrize("rule_id", ["gcp-api-key", "jwt", "jwt-base64"])
def test_public_by_design_keys_say_so(rule_id: str) -> None:
    assert "public" in RULE_NOTES[rule_id]


def test_stripe_note_separates_test_and_live_keys() -> None:
    assert "sk_test_" in RULE_NOTES["stripe-access-token"]
    assert "sk_live_" in RULE_NOTES["stripe-access-token"]


# --- the route ---


@pytest.fixture
def client(db_engine: Engine) -> Iterator[TestClient]:
    yield TestClient(app)
    app.dependency_overrides.clear()


def sign_in(viewer_id: UUID) -> None:
    viewer = Viewer(id=viewer_id, email="person@example.com", name=None)
    app.dependency_overrides[get_viewer] = lambda: viewer


def seed(engine: Engine) -> tuple[UUID, UUID]:
    owner = uuid4()
    with Session(engine) as session:
        session.add(Profile(id=owner))
        session.flush()
        installation = GithubInstallation(
            owner_id=owner, installation_id=7, account_id=70, account_login="me"
        )
        session.add(installation)
        session.flush()
        repo = Repo(
            owner_id=owner,
            installation_id=installation.id,
            github_repo_id=100,
            full_name="me/project",
            is_private=True,
        )
        session.add(repo)
        session.commit()
        return owner, repo.id


def add_scan(engine: Engine, owner: UUID | None, repo: UUID, **overrides: Any) -> UUID:
    fields: dict[str, Any] = {
        "owner_id": owner,
        "repo_id": repo,
        "target_type": TargetType.REPO,
        "target": "me/project",
        "mode": ScanMode.FULL,
        "status": ScanJobStatus.DONE,
    }
    with Session(engine) as session:
        scan = Scan(**(fields | overrides))
        session.add(scan)
        session.commit()
        return scan.id


def add_finding(
    engine: Engine,
    scan: UUID,
    repo: UUID,
    rule_id: str = "aws-access-token",
    file_path: str = "a.py",
    **overrides: Any,
) -> None:
    rule = rule_for(rule_id)
    fields: dict[str, Any] = {
        "scan_id": scan,
        "repo_id": repo,
        "check_id": f"secrets.{rule.provider.value}",
        "category": Category.SECRETS,
        "severity": rule.severity,
        "title": rule.title,
        "evidence_masked": rule.mask,
        "location": f"{file_path}:3",
        "rule_id": rule_id,
        "file_path": file_path,
        "line": 3,
        "commit_sha": "c" * 40,
        "fingerprint": f"{rule_id}-{file_path}",
    }
    with Session(engine) as session:
        session.add(FindingRecord(**(fields | overrides)))
        session.commit()


def get(client: TestClient, repo: UUID) -> Any:
    return client.get(f"/api/repos/{repo}/findings")


def test_finding_carries_location_mask_and_guide(client: TestClient, db_engine: Engine) -> None:
    owner, repo = seed(db_engine)
    scan = add_scan(db_engine, owner, repo)
    add_finding(db_engine, scan, repo)
    sign_in(owner)

    body = get(client, repo).json()

    finding = body["findings"][0]
    assert finding["severity"] == "critical"
    assert finding["masked"] == "AKIA****"
    assert (finding["file_path"], finding["line"]) == ("a.py", 3)
    assert finding["commit_sha"] == "c" * 40
    assert finding["guide"]["provider"] == "aws"
    assert finding["guide"]["rotate_steps"]
    assert body["history_warning"] == HISTORY_WARNING


def test_stored_fingerprint_is_not_sent(client: TestClient, db_engine: Engine) -> None:
    owner, repo = seed(db_engine)
    scan = add_scan(db_engine, owner, repo)
    add_finding(db_engine, scan, repo, fingerprint="do-not-send-this")
    sign_in(owner)

    assert "do-not-send-this" not in json.dumps(get(client, repo).json())


def test_most_serious_come_first_with_counts(client: TestClient, db_engine: Engine) -> None:
    owner, repo = seed(db_engine)
    scan = add_scan(db_engine, owner, repo)
    add_finding(db_engine, scan, repo, "generic-api-key")
    add_finding(db_engine, scan, repo, "jwt")
    add_finding(db_engine, scan, repo, "private-key")
    sign_in(owner)

    body = get(client, repo).json()

    assert [item["rule_id"] for item in body["findings"]] == [
        "private-key",
        "generic-api-key",
        "jwt",
    ]
    assert body["counts"] == {"critical": 1, "high": 0, "medium": 1, "low": 1, "info": 0}


def test_first_seen_is_when_the_row_was_created(client: TestClient, db_engine: Engine) -> None:
    owner, repo = seed(db_engine)
    scan = add_scan(db_engine, owner, repo)
    earlier = utc_now() - timedelta(days=3)
    add_finding(db_engine, scan, repo, created_at=earlier)
    sign_in(owner)

    first_seen = get(client, repo).json()["findings"][0]["first_seen_at"]

    assert first_seen.startswith(earlier.strftime("%Y-%m-%dT%H:%M"))


@pytest.mark.parametrize(
    ("rule_id", "has_note"), [("stripe-access-token", True), ("aws-access-token", False)]
)
def test_note_is_included_only_where_a_rule_has_one(
    client: TestClient, db_engine: Engine, rule_id: str, has_note: bool
) -> None:
    owner, repo = seed(db_engine)
    scan = add_scan(db_engine, owner, repo)
    add_finding(db_engine, scan, repo, rule_id)
    sign_in(owner)

    assert (get(client, repo).json()["findings"][0]["note"] is not None) is has_note


def test_finding_whose_guide_was_removed_still_shows(client: TestClient, db_engine: Engine) -> None:
    owner, repo = seed(db_engine)
    scan = add_scan(db_engine, owner, repo)
    add_finding(db_engine, scan, repo, check_id="secrets.removed")
    sign_in(owner)

    assert get(client, repo).json()["findings"][0]["guide"] is None


def test_never_scanned_repo_is_empty(client: TestClient, db_engine: Engine) -> None:
    owner, repo = seed(db_engine)
    sign_in(owner)

    body = get(client, repo).json()

    assert body["findings"] == []
    assert body["latest_scan"] is None
    assert body["counts"]["critical"] == 0


def test_latest_scan_is_the_newest_with_its_reason(client: TestClient, db_engine: Engine) -> None:
    owner, repo = seed(db_engine)
    add_scan(db_engine, owner, repo, created_at=utc_now() - timedelta(hours=1))
    newest = add_scan(db_engine, owner, repo, incomplete_reason="Too big to scan.")
    sign_in(owner)

    latest = get(client, repo).json()["latest_scan"]

    assert latest["id"] == str(newest)
    assert latest["incomplete_reason"] == "Too big to scan."


def test_abandoned_latest_scan_is_reported_as_failed(client: TestClient, db_engine: Engine) -> None:
    owner, repo = seed(db_engine)
    add_scan(
        db_engine,
        owner,
        repo,
        status=ScanJobStatus.RUNNING,
        created_at=utc_now() - timedelta(minutes=20),
    )
    sign_in(owner)

    assert get(client, repo).json()["latest_scan"]["status"] == "failed"


def test_other_peoples_findings_are_hidden(client: TestClient, db_engine: Engine) -> None:
    owner, repo = seed(db_engine)
    scan = add_scan(db_engine, owner, repo)
    add_finding(db_engine, scan, repo)
    sign_in(uuid4())

    assert get(client, repo).status_code == 404


def test_findings_need_sign_in(client: TestClient, db_engine: Engine) -> None:
    _, repo = seed(db_engine)

    assert get(client, repo).status_code == 401


def test_unknown_repo_is_not_found(client: TestClient, db_engine: Engine) -> None:
    sign_in(uuid4())

    assert get(client, uuid4()).status_code == 404


def test_severity_enum_order_is_most_serious_first() -> None:
    assert list(Severity)[0] is Severity.CRITICAL


def test_supabase_legacy_steps_replace_both_keys_before_deactivating() -> None:
    steps = GUIDES["secrets.supabase"].rotate_steps
    legacy = next(step for step in steps if "legacy service_role" in step)

    assert legacy.index("publishable") < legacy.index("deactivate the legacy keys")


def test_stripe_steps_warn_that_expiring_now_breaks_the_app() -> None:
    assert any("Now stops" in step for step in GUIDES["secrets.stripe"].rotate_steps)


# --- the repo list ---


def test_repo_list_has_counts_and_latest_scan(client: TestClient, db_engine: Engine) -> None:
    owner, repo = seed(db_engine)
    add_scan(db_engine, owner, repo, created_at=utc_now() - timedelta(hours=1))
    newest = add_scan(db_engine, owner, repo, incomplete_reason="Too big to scan.")
    add_finding(db_engine, newest, repo, "private-key")
    add_finding(db_engine, newest, repo, "aws-access-token")
    add_finding(db_engine, newest, repo, "generic-api-key")
    sign_in(owner)

    item = client.get("/api/repos").json()[0]

    assert item["counts"] == {"critical": 2, "high": 0, "medium": 1, "low": 0, "info": 0}
    assert item["latest_scan"]["id"] == str(newest)
    assert item["latest_scan"]["incomplete_reason"] == "Too big to scan."


def test_repo_list_sends_no_finding_details(client: TestClient, db_engine: Engine) -> None:
    owner, repo = seed(db_engine)
    scan = add_scan(db_engine, owner, repo)
    add_finding(db_engine, scan, repo, file_path="very-private-path.py")
    sign_in(owner)

    text = json.dumps(client.get("/api/repos").json())

    assert "very-private-path" not in text
    assert "AKIA" not in text


def test_never_scanned_repo_in_the_list(client: TestClient, db_engine: Engine) -> None:
    owner, _ = seed(db_engine)
    sign_in(owner)

    item = client.get("/api/repos").json()[0]

    assert item["latest_scan"] is None
    assert sum(item["counts"].values()) == 0
