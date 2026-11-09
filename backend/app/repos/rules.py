"""What each gitleaks rule means: which provider, how serious, and how to show it masked."""

from dataclasses import dataclass
from enum import StrEnum

from app.checks.base import Severity


class Provider(StrEnum):
    AWS = "aws"
    FIREBASE = "firebase"
    SUPABASE = "supabase"
    STRIPE = "stripe"
    GITHUB = "github"
    OPENAI = "openai"
    GENERIC = "generic"


@dataclass(frozen=True)
class SecretRule:
    provider: Provider
    severity: Severity
    # Security: fixed per rule, built from the provider's public key format. gitleaks runs
    # with full redaction, so no character of the real secret is available, or kept.
    mask: str
    title: str


_GITHUB_TITLE = "GitHub token found in your code"
_JWT = SecretRule(
    Provider.GENERIC, Severity.LOW, "eyJ****", "A signed token (JWT) found in your code"
)

_RULES: dict[str, SecretRule] = {
    "aws-access-token": SecretRule(
        Provider.AWS, Severity.CRITICAL, "AKIA****", "AWS access key found in your code"
    ),
    "stripe-access-token": SecretRule(
        Provider.STRIPE, Severity.CRITICAL, "sk_****", "Stripe secret key found in your code"
    ),
    "github-pat": SecretRule(Provider.GITHUB, Severity.CRITICAL, "ghp_****", _GITHUB_TITLE),
    "github-fine-grained-pat": SecretRule(
        Provider.GITHUB, Severity.CRITICAL, "github_pat_****", _GITHUB_TITLE
    ),
    "github-oauth": SecretRule(Provider.GITHUB, Severity.CRITICAL, "gho_****", _GITHUB_TITLE),
    "github-app-token": SecretRule(Provider.GITHUB, Severity.CRITICAL, "ghs_****", _GITHUB_TITLE),
    "github-refresh-token": SecretRule(
        Provider.GITHUB, Severity.CRITICAL, "ghr_****", _GITHUB_TITLE
    ),
    "supabase-secret-key": SecretRule(
        Provider.SUPABASE,
        Severity.CRITICAL,
        "sb_secret_****",
        "Supabase secret key found in your code",
    ),
    "supabase-service-role-jwt": SecretRule(
        Provider.SUPABASE,
        Severity.CRITICAL,
        "eyJ****",
        "Supabase service role key found in your code",
    ),
    "private-key": SecretRule(
        Provider.GENERIC,
        Severity.CRITICAL,
        "-----BEGIN ****",
        "Private key found in your code",
    ),
    "openai-api-key": SecretRule(
        Provider.OPENAI, Severity.HIGH, "sk-****", "OpenAI API key found in your code"
    ),
    # Firebase web keys look like this and are public by design, but so do Gemini keys, which
    # must stay secret. The value isn't kept, so this can't tell them apart and sits in the
    # middle. Firebase service accounts are caught by private-key above.
    "gcp-api-key": SecretRule(
        Provider.FIREBASE,
        Severity.MEDIUM,
        "AIza****",
        "Google or Firebase API key found in your code",
    ),
    # Includes Supabase anon keys, which are public by design.
    "jwt": _JWT,
    "jwt-base64": _JWT,
    # A pattern match on names like "api_key", so it's the most likely to be a false alarm.
    "generic-api-key": SecretRule(
        Provider.GENERIC, Severity.MEDIUM, "****", "Possible secret found in your code"
    ),
}

# gitleaks has rules for hundreds of other services. Those are real credentials too.
_OTHER_SERVICE = SecretRule(Provider.GENERIC, Severity.HIGH, "****", "Secret found in your code")


def rule_for(rule_id: str) -> SecretRule:
    return _RULES.get(rule_id, _OTHER_SERVICE)
