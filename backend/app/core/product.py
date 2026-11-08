"""The product name, read from product.json at the repo root.

That file is the only place the name is set. There is deliberately no fallback: a deploy
missing the file should fail at startup rather than quietly show an old name.

Verification record names (app/checks/ownership.py) don't use this. Customers publish them
in their DNS and on their sites, so a rename must not silently change what we look for.
"""

import json
from pathlib import Path

_PRODUCT_FILE = Path(__file__).resolve().parents[3] / "product.json"

PRODUCT_NAME: str = json.loads(_PRODUCT_FILE.read_text(encoding="utf-8"))["name"]
