from pathlib import Path
from typing import Annotated

from pydantic import Field, IPvAnyAddress, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

ROOT_ENV_FILE = Path(__file__).resolve().parents[3] / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=ROOT_ENV_FILE, extra="ignore")

    # Security: CORS is an explicit allowlist, never "*", so other sites cannot
    # call this API from a visitor's browser.
    cors_origins: Annotated[list[str], NoDecode] = ["http://localhost:3000"]

    # Security: scan traffic identifies itself and links to a page explaining it, so site
    # owners can see who is probing them. Replace the placeholder URL once that page exists.
    scanner_user_agent: str = "ScanKitBot/0.1 (+https://scankit.example/about-scanner)"

    # DNS servers for scan lookups. Empty means use the system's DNS. Security: public
    # resolvers keep scans from seeing internal names served by the host's own DNS.
    scanner_dns_servers: Annotated[list[IPvAnyAddress], NoDecode] = []

    # How long each resolver in the fallback chain gets, in seconds.
    scanner_dns_timeout_seconds: float = Field(default=5.0, gt=0, le=30)

    # Local docker-compose services. Production sets both through the environment.
    # 127.0.0.1, not localhost: the services are published on IPv4 only, and on Windows
    # localhost tries IPv6 first, which stalls every new connection.
    database_url: str = "postgresql+psycopg://scankit:scankit_dev@127.0.0.1:5432/scankit"
    redis_url: str = "redis://127.0.0.1:6379/0"

    # Where rate limit counters live. Empty means Redis, so limits hold across API processes.
    rate_limit_storage_url: str | None = None

    @field_validator("cors_origins", "scanner_dns_servers", mode="before")
    @classmethod
    def split_comma_list(cls, value: object) -> object:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value


settings = Settings()
