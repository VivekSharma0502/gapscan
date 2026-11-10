"""What a combined finding means and how to fix it, in plain language.

Checked against each provider's own documentation, which every guide links to.
"""

from pydantic import BaseModel, ConfigDict

from app.models.correlation import CorrelationKind, MatchConfidence
from app.repos.guides import HISTORY_WARNING

LIKELY_NOTE = (
    "GapScan worked out the project indirectly, so this key may belong to something else. "
    "Treat it as real until you've checked. A likely match never affects your score."
)
_ROTATED_ANSWER = (
    "You told GapScan this key was replaced. GapScan can't check that itself, so it's "
    "recorded as your answer. If a different leak of a key for this project appears, it will "
    "be raised again."
)
ROTATED_NOTE = f"{_ROTATED_ANSWER} It stops affecting your score from your next full scan."
ROTATED_NOT_COUNTED_NOTE = f"{_ROTATED_ANSWER} This scan didn't count it against your score."
SCORE_NOTE = (
    "Your next full scan deducts 25 points and caps your grade at D. This is counted once per "
    "project, and adds nothing if that scan already found this key on your site."
)
# No grade claim here: when the site also exposed this key, its own finding sets the grade.
DEDUCTED_NOTE = (
    "This scan deducted 25 points for this key. It's counted once per project, however many "
    "commits or repositories it appears in."
)


class HistoryStep(BaseModel):
    model_config = ConfigDict(frozen=True)

    text: str
    # Shown apart from the text so it can be copied exactly.
    command: str | None = None


class CombinedGuide(BaseModel):
    model_config = ConfigDict(frozen=True)

    provider_name: str
    what_it_means: str
    # In order. The new key goes live before the old one is removed, so the app stays up.
    rotate_steps: tuple[str, ...]
    rotate_url: str
    docs_url: str
    # Empty when nothing secret was committed, so there's nothing to clean up.
    history_steps: tuple[HistoryStep, ...] = ()


# From GitHub's "Removing sensitive data from a repository". It comes after replacing the key
# on purpose: GitHub says a rotated key may not need a rewrite at all, and a rewrite without
# rotating leaves the key usable by anyone who already copied it.
HISTORY_DOCS_URL = (
    "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/"
    "removing-sensitive-data-from-a-repository"
)
_HISTORY_STEPS = (
    HistoryStep(
        text=(
            "Replace the key first. GitHub says that once a key is replaced, rewriting history "
            "may not be necessary, so decide whether it's worth the disruption below."
        )
    ),
    HistoryStep(
        text=(
            "Merge or close open pull requests, because comments on old diffs can be lost. "
            "Then install git-filter-repo 2.47 or later and make a fresh clone."
        )
    ),
    HistoryStep(
        text=(
            "Remove the file from every commit, using its full path in the repository. To keep "
            "the file and remove only the key, use --replace-text with a file listing it instead."
        ),
        command="git-filter-repo --sensitive-data-removal --invert-paths --path PATH-TO-THE-FILE",
    ),
    HistoryStep(
        text=(
            "Check the result, then push. This can't be undone. Branch protection may need "
            "turning off for a moment, and pushes to refs/pull/ failing is expected."
        ),
        command="git push --force --mirror origin",
    ),
    HistoryStep(
        text=(
            "Tell collaborators to clone again, because a plain pull and push can bring the key "
            "back. Commit hashes change, and signatures on rewritten commits are removed."
        )
    ),
    HistoryStep(
        text=(
            "Forks and existing clones keep their copies, and GitHub can't change those. Ask "
            "fork owners to delete theirs. GitHub Support can clear cached views and old pull "
            "requests, but only helps where replacing the key can't remove the risk."
        )
    ),
)

_GUIDES: dict[CorrelationKind, CombinedGuide] = {
    CorrelationKind.SUPABASE_ADMIN: CombinedGuide(
        provider_name="Supabase",
        what_it_means=(
            "This key belongs to the Supabase project your website uses. It bypasses Row Level "
            "Security, so whoever holds it can read, change or delete all of that project's "
            "data, including your site's users' data. " + HISTORY_WARNING
        ),
        rotate_steps=(
            "If you can see the key being misused, remove it now, even though your app will "
            "break until the new one is in.",
            "Take the key out of your code and load it from your server's environment, or the "
            "new key can leak the same way.",
            "In your Supabase project, open Settings, then API Keys, and create a new secret key.",
            "Put it everywhere the old key was used and redeploy, including Edge Functions and "
            "database webhooks. Check that every part of your app now uses it.",
            "If the leaked key starts with sb_secret_, delete it on the same page. This can't "
            "be undone.",
            "If it starts with eyJ, it's a legacy service_role key. Replace your legacy anon key "
            "with a publishable key in your apps, because the next step turns off both. Then "
            "deactivate the legacy keys on the same page. Don't turn them back on if you find a "
            "missed client, because that restores the leaked key.",
            "For a legacy key, also move to JWT signing keys and revoke the legacy JWT secret, "
            "because anything still trusting that secret can accept the leaked key.",
            "Check your tables and auth logs for changes you don't recognize.",
        ),
        rotate_url="https://supabase.com/dashboard/project/_/settings/api-keys",
        docs_url="https://supabase.com/docs/guides/security/rotate-leaked-api-keys",
        history_steps=_HISTORY_STEPS,
    ),
    CorrelationKind.FIREBASE_ADMIN: CombinedGuide(
        provider_name="Firebase",
        what_it_means=(
            "This service account key belongs to the Firebase project your website uses. It "
            "signs in as your server and isn't limited by Security Rules, so whoever holds it "
            "can reach that project's data. " + HISTORY_WARNING
        ),
        rotate_steps=(
            "In the Firebase console, open Settings, then the Service accounts tab, and choose "
            "Generate New Private Key.",
            "Keep the new file out of your code. Store it securely, point "
            "GOOGLE_APPLICATION_CREDENTIALS at it, and redeploy.",
            "In the Google Cloud console, open the Service accounts page, click the account's "
            "email, then the Keys tab. Find the leaked key, whose ID is in the file's "
            "private_key_id field, and click Delete. This is permanent.",
            "Not sure something has stopped using it? Google suggests disabling it first, which "
            "can be undone. The console can't do that, so use gcloud iam service-accounts keys "
            "disable.",
            "Deleting a key doesn't cancel short-lived credentials already issued from it. If "
            "you think it was used, disable or delete the service account itself, which stops "
            "everything using that account.",
            "Check your data and project activity for changes you don't recognize.",
        ),
        rotate_url="https://console.firebase.google.com/",
        docs_url="https://docs.cloud.google.com/iam/docs/keys-create-delete",
        history_steps=_HISTORY_STEPS,
    ),
    CorrelationKind.FIREBASE_CONFIG: CombinedGuide(
        provider_name="Firebase",
        what_it_means=(
            "This repository and your website use the same Firebase project. That's not a leak "
            "on its own, because a Firebase web config is designed to be in your code. Your "
            "data is protected by Security Rules and App Check, not by keeping the config "
            "secret."
        ),
        rotate_steps=(
            "Check that your Firestore, Realtime Database and Storage rules don't allow public "
            "access.",
            "Make sure any Google API key listed here is restricted to the Firebase APIs your "
            "app uses.",
            "If a listed key is really a Gemini API key, it must never be in your code, so "
            "replace it. Google's keys all look alike, so check which one it is.",
        ),
        rotate_url="https://console.firebase.google.com/",
        docs_url="https://firebase.google.com/docs/projects/api-keys",
    ),
}

_TITLES: dict[CorrelationKind, str] = {
    CorrelationKind.SUPABASE_ADMIN: "Your site's backend admin key {verb} leaked in {repo}",
    CorrelationKind.FIREBASE_ADMIN: "Your site's Firebase admin key {verb} leaked in {repo}",
}


def can_be_rotated(kind: CorrelationKind) -> bool:
    return kind in _TITLES


def guide_for(kind: CorrelationKind) -> CombinedGuide:
    return _GUIDES[kind]


def combined_title(kind: CorrelationKind, confidence: MatchConfidence, repo: str) -> str:
    template = _TITLES.get(kind)
    if template is None:
        return f"{repo} uses the same Firebase project as this site"
    return template.format(
        verb="is" if confidence is MatchConfidence.CONFIRMED else "may be", repo=repo
    )
