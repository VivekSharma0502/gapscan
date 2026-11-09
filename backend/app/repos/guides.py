"""Plain-language explanations of leaked secrets and how to replace them, by check_id."""

from pydantic import BaseModel, ConfigDict

from app.repos.rules import Provider

# Shown with every repo's findings, because it's the mistake people most often make.
HISTORY_WARNING = (
    "Deleting the file or the line doesn't remove a secret. Git keeps every old commit, so "
    "anyone who can see this repository, or who already cloned or forked it, can still read "
    "it. Replace the key first, because that's what makes the leaked copy useless. Cleaning "
    "the history can come afterwards, and on its own is never enough."
)


class SecretGuide(BaseModel):
    model_config = ConfigDict(frozen=True)

    provider: Provider
    provider_name: str
    what_it_means: str
    # In order. Each new key goes live before the old one is removed, so the app stays up.
    rotate_steps: tuple[str, ...]
    # Where to do it. None when it depends on which service the key belongs to.
    rotate_url: str | None


_GUIDES = (
    SecretGuide(
        provider=Provider.AWS,
        provider_name="AWS",
        what_it_means=(
            "This key lets whoever holds it act as this AWS user. Stolen AWS keys are found by "
            "automated scanners within minutes and are often used to run up large bills."
        ),
        rotate_steps=(
            "In the AWS IAM console, open the user this key belongs to, then Security credentials.",
            "Create a new access key.",
            "Put the new key everywhere your app uses it, as an environment variable or in a "
            "secrets manager, and redeploy.",
            "Mark the old key Inactive and check that nothing breaks, then delete it.",
            "Check CloudTrail and your billing page for activity you don't recognize.",
        ),
        rotate_url="https://console.aws.amazon.com/iam/home#/users",
    ),
    SecretGuide(
        provider=Provider.FIREBASE,
        provider_name="Firebase / Google",
        what_it_means=(
            "Google API keys identify your project. A Firebase web key is meant to be in your "
            "front-end code, so it isn't a leak by itself, and your Security Rules are what "
            "protect the data. Other Google API keys can cost you money if they're abused."
        ),
        rotate_steps=(
            "In Google Cloud, open APIs & Services, then Credentials, and find this key.",
            "If it's a Firebase web key, keep it, but restrict it to your app's domains and "
            "only the APIs it needs.",
            "Check that your Firestore, Realtime Database and Storage rules don't allow "
            "public access.",
            "If it's any other key, create a new restricted one, put it in your app and "
            "redeploy, then delete the old one.",
        ),
        rotate_url="https://console.cloud.google.com/apis/credentials",
    ),
    SecretGuide(
        provider=Provider.SUPABASE,
        provider_name="Supabase",
        what_it_means=(
            "This key has full access to your Supabase project and bypasses Row Level "
            "Security, so whoever holds it can read, change or delete all of your data."
        ),
        rotate_steps=(
            "In your Supabase project, open Settings, then API Keys, and create a new secret key.",
            "Put it in your server's environment and redeploy everything that used the old key.",
            "If the leaked key starts with sb_secret_, delete it on the same page once nothing "
            "uses it. This can't be undone.",
            "If it starts with eyJ, it's a legacy service_role key. Replace your legacy anon key "
            "with a publishable key in your apps too, because deactivating turns off both. Then "
            "deactivate the legacy keys on the same page, and revoke the legacy JWT secret by "
            "moving to JWT signing keys.",
            "Never put this key in front-end code. Only your server should have it.",
            "Check your tables and auth logs for changes you don't recognize.",
        ),
        rotate_url="https://supabase.com/dashboard/project/_/settings/api-keys",
    ),
    SecretGuide(
        provider=Provider.STRIPE,
        provider_name="Stripe",
        what_it_means=(
            "This key can act on your Stripe account, including reading customer details and "
            "issuing charges or refunds."
        ),
        rotate_steps=(
            "On the Stripe Dashboard's API keys page, open the ⋯ menu for this key and choose "
            "Rotate key.",
            "Set Expiry to the shortest time that lets you update your app. Choosing Now stops "
            "the old key immediately, and your app will fail until it has the new one.",
            "Copy the new key, which is only shown once. Put it in your server's environment and "
            "redeploy.",
            "From the same menu, choose View request logs, and check recent payments and refunds "
            "for anything you don't recognize.",
        ),
        rotate_url="https://dashboard.stripe.com/apikeys",
    ),
    SecretGuide(
        provider=Provider.GITHUB,
        provider_name="GitHub",
        what_it_means=(
            "This token can act as you on GitHub, up to whatever it was allowed to do. That "
            "can include reading private code or pushing changes to it."
        ),
        rotate_steps=(
            "Open GitHub's token settings and delete this token. Delete it right away, since "
            "you can create a new one in a moment.",
            "If it isn't listed there, it belongs to an app. Revoke that app's access under "
            "Settings, then Applications.",
            "Create a new token with only the permissions and repositories it needs, and a "
            "short expiry.",
            "Put the new token where it's used and redeploy.",
            "Check your account's security log and recent commits for anything unexpected.",
        ),
        rotate_url="https://github.com/settings/tokens",
    ),
    SecretGuide(
        provider=Provider.OPENAI,
        provider_name="OpenAI",
        what_it_means=(
            "Anyone with this key can make OpenAI API calls that are billed to your account."
        ),
        rotate_steps=(
            "On OpenAI's API keys page, create a new secret key.",
            "Put it in your server's environment and redeploy.",
            "Delete the old key on the same page.",
            "Check your usage page for spending you don't recognize, and set a monthly budget "
            "limit.",
        ),
        rotate_url="https://platform.openai.com/api-keys",
    ),
    SecretGuide(
        provider=Provider.GENERIC,
        provider_name="Other service",
        what_it_means=(
            "This looks like a password, key or token. Whoever holds it can use it for "
            "whatever it unlocks."
        ),
        rotate_steps=(
            "Use the file and variable name to work out which service this belongs to.",
            "In that service, create a new key or change the password.",
            "Put the new value in an environment variable or a secrets manager, and redeploy.",
            "Delete or revoke the old one.",
            "Check that service's logs for activity you don't recognize.",
        ),
        rotate_url=None,
    ),
)

GUIDES: dict[str, SecretGuide] = {f"secrets.{guide.provider.value}": guide for guide in _GUIDES}

# Where one rule needs saying differently from the rest of its provider's guide. These hedge,
# because the secret itself is never kept, so GapScan can't look at it to tell which case it is.
RULE_NOTES: dict[str, str] = {
    "stripe-access-token": (
        "If this key starts with sk_test_, it only reaches test data, so it's much less urgent "
        "than this rating suggests. Replace it anyway. A key starting with sk_live_ needs "
        "replacing now."
    ),
    "gcp-api-key": (
        "Firebase web keys are designed to be public, so this is low risk if that's what this is."
    ),
    "jwt": (
        "Often harmless: a Supabase anon key looks like this and is designed to be public. It "
        "only needs replacing if it's a real user's session or a server's token."
    ),
    "jwt-base64": (
        "Often harmless: a Supabase anon key looks like this and is designed to be public. It "
        "only needs replacing if it's a real user's session or a server's token."
    ),
    "generic-api-key": (
        "This was matched from how the line looks, so it may be a placeholder or test value. If "
        "you're sure it isn't a real secret, no action is needed."
    ),
    "private-key": (
        "Replace the whole key pair and remove the old public key wherever it's trusted. If this "
        "came from a Firebase or Google service account file, generate a new key under Project "
        "settings, then Service accounts, and delete the old one in Google Cloud."
    ),
}
