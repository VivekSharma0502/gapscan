from pathlib import Path
from typing import Annotated

from pydantic import Field, IPvAnyAddress, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from app.core.product import PRODUCT_NAME

ROOT_ENV_FILE = Path(__file__).resolve().parents[3] / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=ROOT_ENV_FILE, extra="ignore")

    # Security: CORS is an explicit allowlist, never "*", so other sites cannot
    # call this API from a visitor's browser.
    cors_origins: Annotated[list[str], NoDecode] = ["http://localhost:3000"]

    # Security: scan traffic identifies itself and links to a page explaining it, so site
    # owners can see who is probing them and find out how to contact us.
    scanner_user_agent: str = f"{PRODUCT_NAME.replace(' ', '')}Bot/1.0 (+https://viivek.xyz/bot)"

    # DNS servers for scan lookups. Empty means use the system's DNS. Security: public
    # resolvers keep scans from seeing internal names served by the host's own DNS.
    scanner_dns_servers: Annotated[list[IPvAnyAddress], NoDecode] = []

    # How long each resolver in the fallback chain gets, in seconds.
    scanner_dns_timeout_seconds: float = Field(default=5.0, gt=0, le=30)

    # Local docker-compose services. Production sets both through the environment.
    # 127.0.0.1, not localhost: the services are published on IPv4 only, and on Windows
    # localhost tries IPv6 first, which stalls every new connection.
    database_url: str = "postgresql+psycopg://gapscan:gapscan_dev@127.0.0.1:5432/gapscan"
    redis_url: str = "redis://127.0.0.1:6379/0"

    # Where rate limit counters live. Empty means Redis, so limits hold across API processes.
    rate_limit_storage_url: str | None = None

    # The Supabase project URL, e.g. https://abcd.supabase.co. Tokens are verified against
    # its public keys. Empty means sign-in is off and any token is refused with a 503.
    supabase_url: str = ""
    # The publishable key, needed to ask Supabase which GitHub account a user signed in with.
    # Not a secret: it grants nothing without the user's own access token.
    supabase_publishable_key: str = ""

    # The GitHub App. Empty means repo scanning is off.
    github_app_id: str = ""
    # The app's URL name, as in github.com/apps/<slug>.
    github_app_slug: str = ""
    # Security: SecretStr keeps both out of logs, reprs and tracebacks. The key is base64 so
    # the multi-line .pem fits on one env line, the same way locally and in production.
    github_app_private_key_b64: SecretStr = SecretStr("")
    github_webhook_secret: SecretStr = SecretStr("")

    # The gitleaks program. A full path if it isn't on the worker's PATH.
    gitleaks_path: str = "gitleaks"

    @field_validator("supabase_url")
    @classmethod
    def strip_trailing_slash(cls, value: str) -> str:
        # The token issuer is compared exactly, so a pasted trailing slash would reject all.
        return value.strip().rstrip("/")

    @field_validator("cors_origins", "scanner_dns_servers", mode="before")
    @classmethod
    def split_comma_list(cls, value: object) -> object:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value


settings = Settings()
