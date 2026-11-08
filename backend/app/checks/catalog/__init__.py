"""Plain-language text and platform fixes for every check, keyed by check_id."""

from app.checks.base import CheckText
from app.checks.catalog import cms, cookies, dns_email, headers, tls

CATALOG: dict[str, CheckText] = {
    **tls.TEXT,
    **headers.TEXT,
    **cookies.TEXT,
    **dns_email.TEXT,
    **cms.TEXT,
}
