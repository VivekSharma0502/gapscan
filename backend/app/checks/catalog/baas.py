"""Text for the checks on backends a verified site uses."""

from app.checks.base import BackendFix, CheckText, Fix

TEXT: dict[str, CheckText] = {
    "baas.supabase_service_key": CheckText(
        title="Supabase server-only key is in your website's code",
        fix=Fix(
            what_it_means=(
                "This key bypasses Row Level Security, and it's in code that every visitor's "
                "browser downloads. Anyone can copy it and read, change or delete all of your "
                "data. Treat it as already stolen."
            ),
            how_to_fix=(
                "Replace the key in your Supabase project first, because removing it from your "
                "code doesn't undo the leak. Then make sure only your server uses the new key. "
                "Browser code should use your publishable key."
            ),
            backend=BackendFix(
                label="Supabase",
                docs_url="https://supabase.com/docs/guides/security/rotate-leaked-api-keys",
            ),
        ),
    ),
    "baas.backends_found": CheckText(
        title="Backends found in your website's code",
        fix=Fix(
            what_it_means=(
                "Your site's code names these Firebase or Supabase backends. GapScan hasn't "
                "tested them, because code on your site can point at a service that belongs to "
                "someone else, such as a vendor's widget."
            ),
            how_to_fix=(
                "Nothing is wrong yet. On the My domains page, mark the ones that are yours. "
                "GapScan can then check whether their data is open to the public."
            ),
            backend=BackendFix(label="GapScan"),
        ),
    ),
}
