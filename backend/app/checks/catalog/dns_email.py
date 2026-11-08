"""Text for DNS and email authentication checks."""

from app.checks.base import CheckText, Fix, Platform, PlatformFix
from app.checks.catalog._common import dns_record_fixes

_SPF_SENDING_NOTE = (
    "If this domain sends email, use your provider's value instead. For Google Workspace:\n"
    "v=spf1 include:_spf.google.com ~all"
)
_DMARC_SENDING_NOTE = (
    "If this domain sends email, start by monitoring so real mail isn't blocked:\n"
    "v=DMARC1; p=none; rua=mailto:you@example.com"
)

TEXT: dict[str, CheckText] = {
    "dns.spf_missing": CheckText(
        title="No SPF record for email",
        fix=Fix(
            what_it_means=(
                "SPF lists the servers allowed to send email for your domain. Without it, "
                "scammers have an easier time sending fake emails that appear to come from "
                "you, and your real emails are more likely to land in spam."
            ),
            how_to_fix=(
                "Add a TXT record at your domain's root. If the domain never sends email, use "
                "v=spf1 -all. If it does, use the value your email provider gives you, because "
                "a wrong SPF record can block your real email."
            ),
            platforms=dns_record_fixes("TXT", "@", "v=spf1 -all", _SPF_SENDING_NOTE),
        ),
    ),
    "dns.spf_weak": CheckText(
        title="SPF record does not protect your domain",
        fix=Fix(
            what_it_means=(
                "Your SPF record exists but doesn't work as protection. Either it allows any "
                "server to send as you, or there is more than one SPF record, which makes "
                "receiving mail servers treat SPF as broken."
            ),
            how_to_fix=(
                "Keep one SPF record and end it with -all or ~all. Merge multiple records into "
                "one, keeping every include from your email providers."
            ),
            platforms=dns_record_fixes(
                "TXT", "@", "v=spf1 include:your-mail-provider.example -all"
            ),
        ),
    ),
    "dns.dmarc_missing": CheckText(
        title="No DMARC record for email",
        fix=Fix(
            what_it_means=(
                "DMARC tells receiving mail servers what to do with email that fails your "
                "domain's checks. Without it, fake emails using your domain are much more "
                "likely to reach people's inboxes."
            ),
            how_to_fix=(
                "Add a TXT record named _dmarc. If the domain never sends email, use "
                "v=DMARC1; p=reject. If it does, start with p=none and tighten it once the "
                "reports show your real email passes."
            ),
            platforms=dns_record_fixes("TXT", "_dmarc", "v=DMARC1; p=reject", _DMARC_SENDING_NOTE),
        ),
    ),
    "dns.dmarc_weak": CheckText(
        title="DMARC only monitors and blocks nothing",
        fix=Fix(
            what_it_means=(
                "Your DMARC policy is set to none, or has no valid policy, so email that fails "
                "your domain's checks is still delivered. That is fine for a short monitoring "
                "period, but it doesn't stop anyone impersonating you."
            ),
            how_to_fix=(
                "Check your DMARC reports to confirm your real email passes, then change the "
                "policy to p=quarantine, and later to p=reject."
            ),
            platforms=dns_record_fixes(
                "TXT", "_dmarc", "v=DMARC1; p=quarantine; rua=mailto:you@example.com"
            ),
        ),
    ),
    "dns.caa_missing": CheckText(
        title="No CAA record",
        fix=Fix(
            what_it_means=(
                "CAA records name the certificate authorities allowed to issue certificates "
                "for your domain. Without one, any authority may do so, which slightly raises "
                "the risk of a certificate being issued by mistake or through fraud."
            ),
            how_to_fix=(
                'Add a CAA record such as 0 issue "letsencrypt.org". Check which authority '
                "your host uses first, because a CAA record that leaves it out will stop your "
                "certificates from renewing."
            ),
            platforms={
                **dns_record_fixes("CAA", "@", '0 issue "letsencrypt.org"'),
                Platform.CLOUDFLARE: PlatformFix(
                    instructions=(
                        "Open DNS, then Records, and add a CAA record for any authority you "
                        "use yourself. For proxied sites, Cloudflare adds the records its own "
                        "certificate authorities need once a CAA record exists."
                    ),
                    snippet='Type: CAA\nName: @\nValue: 0 issue "letsencrypt.org"',
                ),
            },
        ),
    ),
    "dns.shared_platform_domain": CheckText(
        title="Email and CAA checks don't apply to this shared domain",
        fix=Fix(
            what_it_means=(
                "Your site is on a domain shared by many customers of the platform. Its "
                "SPF, DMARC and CAA records belong to the platform, and you can't change them, "
                "so we skipped those checks instead of marking you down. This doesn't lower "
                "your score."
            ),
            how_to_fix=(
                "Nothing to fix. If you connect your own domain later, scan that domain to "
                "include these checks."
            ),
            platforms={
                Platform.VERCEL: PlatformFix(
                    instructions="To use your own domain, open Project Settings, then Domains.",
                ),
                Platform.NETLIFY: PlatformFix(
                    instructions="To use your own domain, open Domain management.",
                ),
                Platform.NGINX: PlatformFix(
                    instructions="Nothing to change in nginx. These records live in DNS.",
                ),
                Platform.CLOUDFLARE: PlatformFix(
                    instructions=(
                        "To manage these records yourself, add your own domain to Cloudflare."
                    ),
                ),
            },
        ),
    ),
}
