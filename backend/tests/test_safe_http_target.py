import pytest

from app.core.safe_http import BlockedTargetError, normalize_scan_target


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("example.com", "example.com"),
        ("  Example.COM  ", "example.com"),
        ("example.com.", "example.com"),
        ("https://www.example.com/path?q=1#top", "www.example.com"),
        ("http://example.com:80", "example.com"),
        ("https://example.com:443/", "example.com"),
        ("shop.example.co.in", "shop.example.co.in"),
        ("münchen.example", "xn--mnchen-3ya.example"),
    ],
)
def test_accepts_public_names(value: str, expected: str) -> None:
    assert normalize_scan_target(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "localhost",
        "app.localhost",
        "printer.local",
        "db.internal",
        "singlelabel",
        "127.0.0.1",
        "10.0.0.1",
        "8.8.8.8",
        "2130706433",
        "0x7f.0.0.1",
        "[::1]",
        "[2001:4860:4860::8888]",
        "http://[::ffff:127.0.0.1]/",
        "https://example.com:8080/",
        "https://user:secret@example.com/",
        "ftp://example.com/",
        "file:///etc/passwd",
        "gopher://example.com/",
        "exa mple.com",
        "example.com\r\nHost: evil.example",
        ("a" * 60 + ".") * 5 + "com",
    ],
)
def test_refuses_anything_else(value: str) -> None:
    with pytest.raises(BlockedTargetError):
        normalize_scan_target(value)
