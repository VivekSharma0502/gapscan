import json
from pathlib import Path

from app.core.config import Settings
from app.core.product import PRODUCT_NAME
from app.main import app

PRODUCT_FILE = Path(__file__).resolve().parents[2] / "product.json"


def test_name_comes_from_the_shared_file() -> None:
    assert PRODUCT_NAME == json.loads(PRODUCT_FILE.read_text(encoding="utf-8"))["name"]


def test_api_title_uses_the_name() -> None:
    assert app.title == f"{PRODUCT_NAME} API"


def test_default_user_agent_uses_the_name() -> None:
    default = Settings.model_fields["scanner_user_agent"].default

    assert default.startswith(f"{PRODUCT_NAME.replace(' ', '')}Bot/")
