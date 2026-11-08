"""Fixture builders for check tests."""

import httpx

from app.core.safe_http import SafeResponse

Headers = dict[str, str] | list[tuple[str, str]]


def response(
    headers: Headers | None = None,
    body: bytes = b"",
    url: str = "https://example.com/",
    status: int = 200,
    redirects: tuple[str, ...] = (),
) -> SafeResponse:
    return SafeResponse(
        url=url,
        status_code=status,
        headers=httpx.Headers(headers or {}),
        content=body,
        truncated=False,
        redirects=redirects,
    )
