"""Passive CMS checks. Only the homepage already fetched is read, so no extra paths are probed."""

import re
from html.parser import HTMLParser

from app.checks.base import Category, Finding, Input, ScanContext, Severity
from app.checks.registry import check, make_finding

# The generator tag lives in <head>. Scanned sites control this HTML, so the amount parsed
# is limited to keep a huge page from tying up a worker.
MAX_HTML_BYTES = 512 * 1024

_WORDPRESS_RE = re.compile(r"\bWordPress\s+(\d+(?:\.\d+)+)", re.IGNORECASE)


class _GeneratorParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.generators: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "meta":
            return
        values = {name: value or "" for name, value in attrs}
        if values.get("name", "").lower() == "generator":
            self.generators.append(values.get("content", ""))


@check("cms.wordpress_version", Category.CMS, requires=[Input.HTTPS])
def wordpress_version(ctx: ScanContext) -> Finding | None:
    parser = _GeneratorParser()
    parser.feed(ctx.https.content[:MAX_HTML_BYTES].decode("utf-8", "replace"))
    for generator in parser.generators:
        match = _WORDPRESS_RE.search(generator)
        if match:
            return make_finding(
                "cms.wordpress_version",
                Severity.LOW,
                f"Homepage generator tag shows WordPress {match.group(1)}",
            )
    return None
