import pytest

from app.checks import cms
from app.checks.base import Category, ScanContext, Severity
from tests.checks.helpers import response


def ctx(html: str | bytes) -> ScanContext:
    body = html.encode() if isinstance(html, str) else html
    return ScanContext(hostname="example.com", https=response(body=body))


@pytest.mark.parametrize(
    "html",
    [
        '<meta name="generator" content="WordPress 6.4.2" />',
        "<META NAME='GENERATOR' CONTENT='WordPress 6.4.2'>",
        '<meta content="WordPress 6.4.2" name="generator">',
        '<html><head><title>x</title><meta name="generator" content="WordPress 6.4.2"></head>',
    ],
)
def test_wordpress_version_found(html: str) -> None:
    finding = cms.wordpress_version(ctx(html))
    assert finding is not None
    assert finding.severity is Severity.LOW
    assert finding.category is Category.CMS
    assert "6.4.2" in finding.evidence


def test_finds_wordpress_among_several_generators() -> None:
    html = (
        '<meta name="generator" content="Elementor 3.1">'
        '<meta name="generator" content="WordPress 6.0">'
    )
    finding = cms.wordpress_version(ctx(html))
    assert finding is not None
    assert "WordPress 6.0" in finding.evidence


@pytest.mark.parametrize(
    "html",
    [
        "",
        "<html><body>plain page</body></html>",
        '<meta name="generator" content="Hugo 0.120">',
        '<meta name="generator" content="WordPress">',
        '<meta name="generator" content="WordPress.com">',
        '<meta name="description" content="WordPress 6.4.2 tips">',
        "<p>WordPress 6.4.2 was released</p>",
        '<meta name="generator">',
    ],
)
def test_no_version_passes(html: str) -> None:
    assert cms.wordpress_version(ctx(html)) is None


@pytest.mark.parametrize("html", [b"\xff\xfe\x00", b"<meta <<< name=", b"<!doctype <![CDATA[ <"])
def test_malformed_html_does_not_crash(html: bytes) -> None:
    assert cms.wordpress_version(ctx(html)) is None


def test_only_start_of_large_page_is_parsed() -> None:
    padding = b"x" * cms.MAX_HTML_BYTES
    assert (
        cms.wordpress_version(ctx(padding + b'<meta name="generator" content="WordPress 6.0">'))
        is None
    )
