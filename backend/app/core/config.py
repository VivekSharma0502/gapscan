from pathlib import Path
from typing import Annotated

from pydantic import field_validator
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

    @field_validator("cors_origins", mode="before")
    @classmethod
    def split_origins(cls, value: object) -> object:
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value


settings = Settings()
