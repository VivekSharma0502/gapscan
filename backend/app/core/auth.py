"""Who is making a request: verifies Supabase access tokens.

Tokens are checked against Supabase's published public keys, so this backend holds no
secret that could be used to mint a valid token.
"""

import json
import logging
import math
import threading
from dataclasses import dataclass
from time import monotonic
from typing import Annotated, Any
from uuid import UUID

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWK, PyJWKSet
from pydantic import BaseModel, ConfigDict, ValidationError
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session

from app.core.config import settings
from app.core.safe_http import SafeHttpError, safe_api_request, safe_get
from app.models.profile import MAX_EMAIL_LENGTH, MAX_NAME_LENGTH, Profile

logger = logging.getLogger(__name__)

# Security: asymmetric only. Accepting "none" would skip the signature, and accepting HS256
# would let an attacker sign a token using the public key as a shared secret.
ALLOWED_ALGORITHMS = frozenset({"ES256", "RS256"})
EXPECTED_AUDIENCE = "authenticated"
CLOCK_LEEWAY_SECONDS = 30

# Supabase's edge caches this endpoint for 10 minutes and advises not holding keys for more
# than 20, so a revoked key stops working here within that time.
KEYS_REFRESH_AFTER_SECONDS = 600.0
KEYS_EXPIRE_AFTER_SECONDS = 1200.0
# Security: the "kid" comes from an unverified token. Without this limit, a stream of forged
# tokens with made-up kids would turn every request into an outbound fetch.
REFETCH_COOLDOWN_SECONDS = 30.0


class AuthUnavailableError(Exception):
    """The signing keys can't be obtained, so no token can be checked right now."""


@dataclass(frozen=True)
class Viewer:
    id: UUID
    email: str | None
    name: str | None


def _jwks_url() -> str:
    return f"{settings.supabase_url}/auth/v1/.well-known/jwks.json"


def _fetch_signing_keys() -> dict[str, PyJWK]:
    # Security: fetched through the SSRF guard rather than PyJWT's own PyJWKClient, which
    # would make an outbound request outside safe_http.
    try:
        response = safe_get(_jwks_url())
    except SafeHttpError as exc:
        raise AuthUnavailableError("could not reach the JWKS endpoint") from exc
    if response.status_code != 200 or response.truncated:
        raise AuthUnavailableError(f"JWKS endpoint returned {response.status_code}")

    try:
        document = json.loads(response.content)
    except ValueError as exc:
        raise AuthUnavailableError("JWKS endpoint returned invalid JSON") from exc
    if isinstance(document, dict) and document.get("keys") == []:
        raise AuthUnavailableError(
            "JWKS is empty: the Supabase project still uses the legacy HS256 secret. "
            "Switch it to asymmetric JWT signing keys."
        )

    try:
        key_set = PyJWKSet.from_dict(document)
    except (jwt.PyJWTError, TypeError, AttributeError) as exc:
        raise AuthUnavailableError("JWKS endpoint returned no usable keys") from exc
    return {
        key.key_id: key
        for key in key_set.keys
        if key.key_id is not None and key.algorithm_name in ALLOWED_ALGORITHMS
    }


class _SigningKeys:
    """In-memory signing keys, shared by the API's worker threads."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._keys: dict[str, PyJWK] = {}
        self._fetched_at: float | None = None
        self._last_attempt: float | None = None

    def get(self, kid: str) -> PyJWK:
        with self._lock:
            refresh_error = self._refresh_if_needed(kid)
            age = math.inf if self._fetched_at is None else monotonic() - self._fetched_at
            if age >= KEYS_EXPIRE_AFTER_SECONDS:
                raise refresh_error or AuthUnavailableError("signing keys have expired")
            key = self._keys.get(kid)
            if key is not None:
                return key
            # A key we couldn't look up isn't proof the token is bad, so don't reject it.
            if refresh_error is not None:
                raise refresh_error
            raise jwt.InvalidTokenError("unknown signing key")

    def _refresh_if_needed(self, kid: str) -> AuthUnavailableError | None:
        now = monotonic()
        stale = self._fetched_at is None or now - self._fetched_at >= KEYS_REFRESH_AFTER_SECONDS
        if not stale and kid in self._keys:
            return None
        if self._last_attempt is not None:
            if now - self._last_attempt < REFETCH_COOLDOWN_SECONDS:
                return None
        self._last_attempt = now
        try:
            self._keys = _fetch_signing_keys()
        except AuthUnavailableError as exc:
            # Keys that are stale but unexpired keep working through a short outage.
            logger.error("could not refresh signing keys: %s", exc)
            return exc
        self._fetched_at = monotonic()
        return None


_signing_keys = _SigningKeys()


def _text_claim(value: object, max_length: int) -> str | None:
    # user_metadata can be edited by the user it describes. Postgres rejects NUL in text, so
    # letting one through would turn a crafted profile into a server error.
    if not isinstance(value, str) or not value or len(value) > max_length or "\x00" in value:
        return None
    return value


def _viewer_from_claims(claims: dict[str, Any]) -> Viewer:
    # Security: Supabase's anonymous sign-ins produce valid tokens with no real account, and
    # those must not count as signing up for the full report.
    if claims.get("is_anonymous") is True:
        raise jwt.InvalidTokenError("anonymous user")
    try:
        user_id = UUID(claims["sub"])
    except (ValueError, TypeError, AttributeError) as exc:
        raise jwt.InvalidTokenError("subject is not a user id") from exc

    metadata = claims.get("user_metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    name = metadata.get("full_name") or metadata.get("name") or metadata.get("user_name")
    return Viewer(
        id=user_id,
        email=_text_claim(claims.get("email"), MAX_EMAIL_LENGTH),
        name=_text_claim(name, MAX_NAME_LENGTH),
    )


def verify_access_token(token: str) -> Viewer:
    """Return the token's user, or raise jwt.PyJWTError if it can't be trusted."""
    if not settings.supabase_url:
        raise AuthUnavailableError("SUPABASE_URL is not set")

    header = jwt.get_unverified_header(token)
    kid = header.get("kid")
    if header.get("alg") not in ALLOWED_ALGORITHMS or not isinstance(kid, str):
        raise jwt.InvalidAlgorithmError("token is not signed with an accepted key type")

    signing_key = _signing_keys.get(kid)
    # Security: the algorithm comes from the key we trust, never from the token's header.
    claims = jwt.decode(
        token,
        key=signing_key.key,
        algorithms=[signing_key.algorithm_name],
        audience=EXPECTED_AUDIENCE,
        issuer=f"{settings.supabase_url}/auth/v1",
        leeway=CLOCK_LEEWAY_SECONDS,
        options={"require": ["exp", "iss", "aud", "sub"]},
    )
    return _viewer_from_claims(claims)


_bearer = HTTPBearer(auto_error=False)


def get_viewer(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> Viewer | None:
    """Return the signed-in user, or None for a request with no token.

    Security: a token that fails is an error, not an anonymous request, so a broken session
    is visible instead of silently becoming a logged-out one.
    """
    if credentials is None:
        return None
    try:
        return verify_access_token(credentials.credentials)
    except jwt.PyJWTError as exc:
        # Security: only the error type is logged. The token itself is a credential.
        logger.info("rejected access token: %s", type(exc).__name__)
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail="Your session has expired. Please sign in again.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    except AuthUnavailableError as exc:
        logger.error("cannot verify access tokens: %s", exc)
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Sign-in is unavailable right now. Please try again shortly.",
        ) from exc


def require_viewer(viewer: Annotated[Viewer | None, Depends(get_viewer)]) -> Viewer:
    if viewer is None:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail="Sign in to continue.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return viewer


def require_access_token(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> str:
    """Return the caller's raw token, for a route that must act as them towards Supabase."""
    if credentials is None:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail="Sign in to continue.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return credentials.credentials


class _SupabaseIdentity(BaseModel):
    model_config = ConfigDict(hide_input_in_errors=True)

    provider: str
    # The provider's own user id, set by Supabase when the provider confirmed the sign-in.
    id: str


class _SupabaseUser(BaseModel):
    model_config = ConfigDict(hide_input_in_errors=True)

    id: UUID
    identities: list[_SupabaseIdentity] | None = None


def fetch_github_account_id(access_token: str, viewer_id: UUID) -> int | None:
    """Return the GitHub user id this person signed in with, or None if they never did.

    Security: asks Supabase instead of reading the access token's user_metadata. A user can
    edit their own user_metadata with an ordinary API call, so a GitHub id or username there
    would let anyone claim to be anyone. Identities can only come from a completed sign-in.
    """
    if not settings.supabase_url or not settings.supabase_publishable_key:
        raise AuthUnavailableError("SUPABASE_URL or SUPABASE_PUBLISHABLE_KEY is not set")
    try:
        response = safe_api_request(
            "GET",
            f"{settings.supabase_url}/auth/v1/user",
            headers={
                "apikey": settings.supabase_publishable_key,
                "Authorization": f"Bearer {access_token}",
            },
        )
    except SafeHttpError as exc:
        raise AuthUnavailableError("could not reach Supabase") from exc
    if response.status_code != 200 or response.truncated:
        raise AuthUnavailableError(f"Supabase returned {response.status_code}")
    try:
        user = _SupabaseUser.model_validate_json(response.content)
    except ValidationError:
        raise AuthUnavailableError("Supabase returned an unexpected response") from None
    if user.id != viewer_id:
        raise AuthUnavailableError("Supabase returned a different user")

    for identity in user.identities or []:
        if identity.provider == "github" and identity.id.isascii() and identity.id.isdigit():
            return int(identity.id)
    return None


def ensure_profile(session: Session, viewer: Viewer) -> None:
    """Create or update the viewer's profile, in the caller's transaction.

    Called on write routes only, so polling a scan stays read-only. App data lives in a
    different database from Supabase Auth, which rules out a database trigger on signup.
    """
    profile = session.get(Profile, viewer.id)
    if profile is None:
        try:
            with session.begin_nested():
                session.add(Profile(id=viewer.id, email=viewer.email, name=viewer.name))
        except IntegrityError:
            # A simultaneous first request from the same user created the row.
            pass
        return
    profile.email = viewer.email or profile.email
    profile.name = viewer.name or profile.name
