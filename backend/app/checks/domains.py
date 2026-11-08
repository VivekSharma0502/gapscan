"""Domain name helpers built on the Public Suffix List."""

from publicsuffixlist import PublicSuffixList

# The full list includes platform domains such as vercel.app. The ICANN-only list has
# just real registry suffixes such as .app and .co.in, and the difference reveals platforms.
_ALL_SUFFIXES = PublicSuffixList(only_icann=False)
_ICANN_SUFFIXES = PublicSuffixList(only_icann=True)


def _normalise(hostname: str) -> str:
    return hostname.lower().rstrip(".")


def registrable_domain(hostname: str) -> str | None:
    """Return the domain someone actually registered, or None for a bare suffix.

    Taking the last two labels would be wrong for names like shop.example.co.in.
    """
    return _ALL_SUFFIXES.privatesuffix(_normalise(hostname))


def shared_platform_suffix(hostname: str) -> str | None:
    """Return the platform suffix for hosts like foo.vercel.app, otherwise None."""
    name = _normalise(hostname)
    suffix = _ALL_SUFFIXES.publicsuffix(name)
    return suffix if suffix != _ICANN_SUFFIXES.publicsuffix(name) else None
