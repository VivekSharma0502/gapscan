"""Who is making a request."""

from uuid import UUID


def get_viewer_id() -> UUID | None:
    """Return the signed-in user's id, or None for an anonymous request.

    Accounts arrive in Phase 2, which will verify the Supabase JWT here. Until then every
    request is anonymous, so no API path can return a full report.
    """
    return None
