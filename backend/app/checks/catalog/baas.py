"""Text for the checks on backends a verified site uses."""

from app.checks.base import BackendFix, CheckText, Fix

_RULES_DOCS = "https://firebase.google.com/docs/rules/basics"

_RTDB_OWNER_RULES = """{
  "rules": {
    "users": {
      "$uid": {
        ".read": "auth !== null && auth.uid === $uid",
        ".write": "auth !== null && auth.uid === $uid"
      }
    }
  }
}"""

_STORAGE_OWNER_RULES = """rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /user/{userId}/{fileName} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
  }
}"""

TEXT: dict[str, CheckText] = {
    "baas.firebase_rtdb_public": CheckText(
        title="Firebase database is readable by anyone",
        fix=Fix(
            what_it_means=(
                "Your database rules let anyone on the internet read the whole database, without "
                "signing in. GapScan only counted its top-level keys and read nothing else, but "
                "anyone else could download all of it, so treat what's stored there as exposed."
            ),
            how_to_fix=(
                "In the Firebase console, open Realtime Database, then Rules, and replace the "
                "open rule with one that checks who is asking. This example lets each signed-in "
                "user reach only their own data under /users, so change the path to match how "
                "your data is laid out, then test your app before relying on it."
            ),
            backend=BackendFix(
                label="Firebase",
                snippet=_RTDB_OWNER_RULES,
                docs_url=_RULES_DOCS,
            ),
        ),
    ),
    "baas.firebase_storage_listable": CheckText(
        title="Anyone can list the files in your Firebase storage",
        fix=Fix(
            what_it_means=(
                "Your storage rules let anyone see the name of every file in this bucket, "
                "without signing in. File names often reveal users and documents, and a list "
                "makes it easy to find and download everything."
            ),
            how_to_fix=(
                "In the Firebase console, open Storage, then Rules. This example lets each "
                "signed-in user reach only their own folder, so change the path to match yours. "
                "If some files really must be public, use allow get for those instead of allow "
                "read, so they can be downloaded by link but not listed."
            ),
            backend=BackendFix(
                label="Firebase",
                snippet=_STORAGE_OWNER_RULES,
                docs_url=_RULES_DOCS,
            ),
        ),
    ),
    "baas.firebase_rtdb_protected": CheckText(
        title="Checked: database not publicly readable",
        fix=Fix(
            what_it_means=(
                "GapScan asked for the top of your database without signing in, and it was "
                "refused. This only tests the top level, so rules on specific paths could still "
                "be more open."
            ),
            how_to_fix="Nothing to do. If your rules open up specific paths, review those too.",
            backend=BackendFix(label="Firebase", docs_url=_RULES_DOCS),
        ),
    ),
    "baas.firebase_storage_protected": CheckText(
        title="Checked: storage files can't be listed publicly",
        fix=Fix(
            what_it_means=(
                "GapScan asked for a list of this bucket's files without signing in, and it was "
                "refused. A single file could still be public if your rules allow it and someone "
                "knows its name."
            ),
            how_to_fix="Nothing to do. If some files are meant to be private, review their rules.",
            backend=BackendFix(label="Firebase", docs_url=_RULES_DOCS),
        ),
    ),
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
    "baas.scripts_unread": CheckText(
        title="Some of your website's scripts couldn't be read",
        fix=Fix(
            what_it_means=(
                "GapScan looks through your site's scripts for Firebase and Supabase settings. "
                "It couldn't read every script, so it can't say whether your site uses those "
                "services, and a key in an unread script would have been missed."
            ),
            how_to_fix=(
                "The list above says why each script was skipped. If it says bot protection "
                "blocked it, GapScan won't try to get past that, because it's your site's choice. "
                "To let scans through, add a firewall rule that allows requests whose user agent "
                "contains GapScanBot, then scan again. A user agent can be faked, so remove the "
                "rule when you're done if you don't scan regularly."
            ),
            backend=BackendFix(label="GapScan"),
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
