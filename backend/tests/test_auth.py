import base64
import hashlib
import hmac
import json
from collections.abc import Iterator
from time import time
from types import SimpleNamespace
from typing import Any
from uuid import UUID, uuid4

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from jwt.algorithms import ECAlgorithm
from sqlalchemy import Engine
from sqlmodel import Session

from app.core import auth
from app.core.auth import AuthUnavailableError, Viewer, ensure_profile, verify_access_token
from app.core.config import Settings, settings
from app.core.rate_limit import limiter
from app.core.safe_http import RequestFailedError
from app.main import app
from app.models.profile import Profile

PROJECT = "https://abcd.supabase.co"
JWKS_URL = f"{PROJECT}/auth/v1/.well-known/jwks.json"
KID = "key-1"
USER_ID = UUID("11111111-2222-4333-8444-555555555555")

SIGNING_KEY = ec.generate_private_key(ec.SECP256R1())
ATTACKER_KEY = ec.generate_private_key(ec.SECP256R1())


def public_jwk(key: ec.EllipticCurvePrivateKey, kid: str = KID) -> dict[str, Any]:
    return json.loads(ECAlgorithm.to_jwk(key.public_key())) | {
        "kid": kid,
        "alg": "ES256",
        "use": "sig",
    }


def claims(**overrides: Any) -> dict[str, Any]:
    fields = {
        "sub": str(USER_ID),
        "iss": f"{PROJECT}/auth/v1",
        "aud": "authenticated",
        "exp": int(time()) + 3600,
        "email": "person@example.com",
        "user_metadata": {"full_name": "Pat Example"},
    }
    return {key: value for key, value in (fields | overrides).items() if value is not None}


def sign(
    payload: dict[str, Any] | None = None,
    key: ec.EllipticCurvePrivateKey = SIGNING_KEY,
    kid: str | None = KID,
) -> str:
    headers = {"kid": kid} if kid is not None else {}
    return jwt.encode(claims() if payload is None else payload, key, "ES256", headers=headers)


class FakeJwks:
    """Stands in for safe_get, so these tests make no network calls."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.keys = [public_jwk(SIGNING_KEY)]
        self.status_code = 200
        self.truncated = False
        self.body: bytes | None = None
        self.error: Exception | None = None

    def __call__(self, url: str) -> SimpleNamespace:
        self.calls.append(url)
        if self.error is not None:
            raise self.error
        content = self.body if self.body is not None else json.dumps({"keys": self.keys}).encode()
        return SimpleNamespace(
            status_code=self.status_code, truncated=self.truncated, content=content
        )


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def jwks(monkeypatch: pytest.MonkeyPatch) -> FakeJwks:
    fake = FakeJwks()
    monkeypatch.setattr(auth, "safe_get", fake)
    monkeypatch.setattr(auth, "_signing_keys", auth._SigningKeys())
    monkeypatch.setattr(settings, "supabase_url", PROJECT)
    return fake


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> FakeClock:
    fake = FakeClock()
    monkeypatch.setattr(auth, "monotonic", fake)
    return fake


@pytest.fixture
def client(db_engine: Engine, jwks: FakeJwks) -> Iterator[TestClient]:
    limiter.reset()
    yield TestClient(app)
    limiter.reset()


# Accepted tokens


def test_valid_token_returns_the_user(jwks: FakeJwks) -> None:
    assert verify_access_token(sign()) == Viewer(
        id=USER_ID, email="person@example.com", name="Pat Example"
    )
    assert jwks.calls == [JWKS_URL]


def test_the_signing_key_is_chosen_by_key_id(jwks: FakeJwks) -> None:
    jwks.keys = [public_jwk(ATTACKER_KEY, "other"), public_jwk(SIGNING_KEY)]

    assert verify_access_token(sign()).id == USER_ID


def test_recently_expired_token_passes_within_the_clock_leeway(jwks: FakeJwks) -> None:
    assert verify_access_token(sign(claims(exp=int(time()) - 5))).id == USER_ID


def test_github_username_is_the_last_resort_name(jwks: FakeJwks) -> None:
    token = sign(claims(user_metadata={"user_name": "patexample"}))

    assert verify_access_token(token).name == "patexample"


@pytest.mark.parametrize("name", ["x" * 256, "bad\x00name", 12, ""])
def test_unusable_profile_text_is_dropped(jwks: FakeJwks, name: object) -> None:
    # user_metadata is editable by its user, and must not be able to break the insert.
    assert verify_access_token(sign(claims(user_metadata={"full_name": name}))).name is None


# Rejected tokens


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def forge(alg: str, signature: bytes, kid: str = KID) -> str:
    header = b64url(json.dumps({"alg": alg, "typ": "JWT", "kid": kid}).encode())
    body = b64url(json.dumps(claims()).encode())
    return f"{header}.{body}.{b64url(signature)}"


def test_unsigned_token_is_rejected(jwks: FakeJwks) -> None:
    with pytest.raises(jwt.PyJWTError):
        verify_access_token(forge("none", b""))


def test_hs256_signed_with_the_public_key_is_rejected(jwks: FakeJwks) -> None:
    # Security: the classic algorithm confusion attack. The public key is, well, public.
    public_pem = SIGNING_KEY.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    unsigned = forge("HS256", b"").rsplit(".", 1)[0]
    signature = hmac.new(public_pem, unsigned.encode(), hashlib.sha256).digest()

    with pytest.raises(jwt.PyJWTError):
        verify_access_token(f"{unsigned}.{b64url(signature)}")


def test_token_signed_by_another_key_is_rejected(jwks: FakeJwks) -> None:
    with pytest.raises(jwt.PyJWTError):
        verify_access_token(sign(key=ATTACKER_KEY))


def test_tampered_payload_is_rejected(jwks: FakeJwks) -> None:
    header, _, signature = sign().split(".")
    other = b64url(json.dumps(claims(sub=str(uuid4()))).encode())

    with pytest.raises(jwt.PyJWTError):
        verify_access_token(f"{header}.{other}.{signature}")


@pytest.mark.parametrize(
    "bad_claims",
    [
        {"exp": int(time()) - 3600},
        {"iss": "https://evil.supabase.co/auth/v1"},
        {"aud": "anon"},
        {"exp": None},
        {"iss": None},
        {"aud": None},
        {"sub": None},
        {"sub": "not-a-uuid"},
        {"is_anonymous": True},
    ],
    ids=str,
)
def test_token_with_bad_claims_is_rejected(jwks: FakeJwks, bad_claims: dict[str, Any]) -> None:
    with pytest.raises(jwt.PyJWTError):
        verify_access_token(sign(claims(**bad_claims)))


@pytest.mark.parametrize("token", ["garbage", "a.b.c", ""])
def test_malformed_token_is_rejected_without_fetching_keys(jwks: FakeJwks, token: str) -> None:
    with pytest.raises(jwt.PyJWTError):
        verify_access_token(token)
    assert jwks.calls == []


def test_token_without_a_key_id_is_rejected(jwks: FakeJwks) -> None:
    with pytest.raises(jwt.PyJWTError):
        verify_access_token(sign(kid=None))


# Signing key cache


def test_keys_are_cached_between_requests(jwks: FakeJwks, clock: FakeClock) -> None:
    verify_access_token(sign())
    clock.now += 599
    verify_access_token(sign())

    assert len(jwks.calls) == 1


def test_keys_refresh_after_ten_minutes(jwks: FakeJwks, clock: FakeClock) -> None:
    verify_access_token(sign())
    clock.now += 600
    verify_access_token(sign())

    assert len(jwks.calls) == 2


def test_forged_key_ids_cannot_force_repeated_fetches(jwks: FakeJwks, clock: FakeClock) -> None:
    # Security: otherwise each forged token would make this server send a request.
    verify_access_token(sign())
    clock.now += 31

    for attempt in range(25):
        with pytest.raises(jwt.PyJWTError):
            verify_access_token(sign(key=ATTACKER_KEY, kid=f"made-up-{attempt}"))

    assert len(jwks.calls) == 2


def test_a_rotated_in_key_is_picked_up(jwks: FakeJwks, clock: FakeClock) -> None:
    verify_access_token(sign())
    new_key = ec.generate_private_key(ec.SECP256R1())
    jwks.keys = [public_jwk(new_key, "key-2")]
    clock.now += 31

    assert verify_access_token(sign(key=new_key, kid="key-2")).id == USER_ID


def test_a_removed_key_stops_working_after_a_refresh(jwks: FakeJwks, clock: FakeClock) -> None:
    verify_access_token(sign())
    jwks.keys = [public_jwk(ATTACKER_KEY, "key-2")]
    clock.now += 600

    with pytest.raises(jwt.PyJWTError):
        verify_access_token(sign())


def test_keys_survive_a_short_outage(jwks: FakeJwks, clock: FakeClock) -> None:
    verify_access_token(sign())
    jwks.error = RequestFailedError("down")
    clock.now += 700

    assert verify_access_token(sign()).id == USER_ID


def test_keys_are_not_trusted_past_their_limit(jwks: FakeJwks, clock: FakeClock) -> None:
    verify_access_token(sign())
    jwks.error = RequestFailedError("down")
    clock.now += 1200

    with pytest.raises(AuthUnavailableError):
        verify_access_token(sign())


def test_unknown_key_during_an_outage_is_not_called_invalid(
    jwks: FakeJwks, clock: FakeClock
) -> None:
    verify_access_token(sign())
    jwks.error = RequestFailedError("down")
    clock.now += 31

    with pytest.raises(AuthUnavailableError):
        verify_access_token(sign(kid="key-2"))


def test_failed_fetches_are_rate_limited_too(jwks: FakeJwks, clock: FakeClock) -> None:
    jwks.error = RequestFailedError("down")

    for _ in range(5):
        with pytest.raises(AuthUnavailableError):
            verify_access_token(sign())

    assert len(jwks.calls) == 1


# Signing keys that can't be used


def test_empty_jwks_explains_the_legacy_secret(jwks: FakeJwks) -> None:
    jwks.keys = []

    with pytest.raises(AuthUnavailableError, match="legacy HS256"):
        verify_access_token(sign())


def test_symmetric_key_in_jwks_is_never_used(jwks: FakeJwks) -> None:
    secret = b64url(b"s" * 32)
    jwks.keys = [{"kty": "oct", "k": secret, "kid": KID, "alg": "HS256"}]

    with pytest.raises(jwt.PyJWTError):
        verify_access_token(sign())


@pytest.mark.parametrize(
    "broken",
    [
        {"status_code": 500},
        {"truncated": True},
        {"body": b"not json"},
        {"body": b"[1, 2]"},
        {"body": b'{"keys": "nope"}'},
        {"error": RequestFailedError("down")},
    ],
    ids=str,
)
def test_bad_jwks_response_means_unavailable(jwks: FakeJwks, broken: dict[str, Any]) -> None:
    for name, value in broken.items():
        setattr(jwks, name, value)

    with pytest.raises(AuthUnavailableError):
        verify_access_token(sign())


def test_missing_configuration_means_unavailable(
    jwks: FakeJwks, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "supabase_url", "")

    with pytest.raises(AuthUnavailableError):
        verify_access_token(sign())
    assert jwks.calls == []


def test_pasted_trailing_slash_is_removed() -> None:
    assert Settings(supabase_url=f"{PROJECT}/ ").supabase_url == PROJECT


# Through the API


def get_scan(client: TestClient, **headers: str) -> Any:
    # An unknown id, so 404 means authentication passed and the handler ran.
    return client.get(f"/api/scans/{uuid4()}", headers=headers)


def test_request_without_a_token_is_anonymous(client: TestClient, jwks: FakeJwks) -> None:
    assert get_scan(client).status_code == 404
    assert jwks.calls == []


def test_valid_bearer_token_is_accepted(client: TestClient) -> None:
    assert get_scan(client, authorization=f"Bearer {sign()}").status_code == 404


def test_invalid_token_is_401_not_anonymous(client: TestClient) -> None:
    result = get_scan(client, authorization=f"Bearer {sign(key=ATTACKER_KEY)}")

    assert result.status_code == 401
    assert result.headers["www-authenticate"] == "Bearer"


def test_token_is_never_logged(client: TestClient, caplog: pytest.LogCaptureFixture) -> None:
    token = sign(key=ATTACKER_KEY)

    with caplog.at_level("DEBUG"):
        get_scan(client, authorization=f"Bearer {token}")

    assert token not in caplog.text


def test_unreachable_keys_are_503_not_anonymous(client: TestClient, jwks: FakeJwks) -> None:
    jwks.error = RequestFailedError("down")

    assert get_scan(client, authorization=f"Bearer {sign()}").status_code == 503


# Profiles


VIEWER = Viewer(id=USER_ID, email="person@example.com", name="Pat Example")


def test_first_visit_creates_a_free_profile(db_engine: Engine) -> None:
    with Session(db_engine) as session:
        ensure_profile(session, VIEWER)
        session.commit()
        profile = session.get_one(Profile, USER_ID)

        assert (profile.email, profile.name, profile.plan) == (
            "person@example.com",
            "Pat Example",
            "free",
        )


def test_later_visits_update_changed_details(db_engine: Engine) -> None:
    with Session(db_engine) as session:
        ensure_profile(session, VIEWER)
        session.commit()
        ensure_profile(session, Viewer(id=USER_ID, email="new@example.com", name=None))
        session.commit()
        profile = session.get_one(Profile, USER_ID)

        assert (profile.email, profile.name) == ("new@example.com", "Pat Example")


def test_simultaneous_first_visits_do_not_fail(
    db_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    with Session(db_engine) as session:
        session.add(Profile(id=USER_ID))
        session.commit()

    with Session(db_engine) as session:
        # As if another request inserted the row just after this one looked for it.
        monkeypatch.setattr(session, "get", lambda *_args, **_kwargs: None)
        ensure_profile(session, VIEWER)
        session.commit()

    with Session(db_engine) as session:
        assert session.get(Profile, USER_ID) is not None
