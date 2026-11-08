"""Per-client rate limiting."""

from slowapi import Limiter
from slowapi.util import get_remote_address

from app.core.config import settings

# Security: keyed on the connection's address, not on a header the client can forge. Behind
# a proxy this needs uvicorn's --forwarded-allow-ips. See the README's deploy section.
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=settings.rate_limit_storage_url or settings.redis_url,
    # A stalled Redis must fail quickly instead of holding request threads.
    storage_options={"socket_connect_timeout": 2, "socket_timeout": 2},
)
