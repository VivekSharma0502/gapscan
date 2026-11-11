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
    "dns.spf_multiple_records": CheckText(
        title="More than one SPF record",
        fix=Fix(
            what_it_means=(
                "Your domain has several SPF records. The rules say there must be exactly one, "
                "so receiving mail servers treat SPF as broken and ignore all of them. Your "
                "real email may land in spam, and fake email isn't stopped."
            ),
            how_to_fix=(
                "Merge them into one TXT record that starts with v=spf1, keeps every include "
                "from each of your email providers, and ends with -all or ~all. Then delete "
                "the others."
            ),
            platforms=dns_record_fixes(
                "TXT", "@", "v=spf1 include:provider-one.example include:provider-two.example ~all"
            ),
        ),
    ),
    "dns.spf_allow_all": CheckText(
        title="SPF record lets any server send as you",
        fix=Fix(
            what_it_means=(
                "Your SPF record ends with +all (or a bare all), which tells receiving mail "
                "servers that every server on the internet may send email for your domain. "
                "That is worse than having no SPF record: fake emails pass the SPF check, and "
                "that pass can also get them through DMARC."
            ),
            how_to_fix=(
                "Change the ending to -all, or ~all while you confirm your real email still "
                "arrives. Keep the includes your email providers gave you, and make sure every "
                "service that sends as you is listed."
            ),
            platforms=dns_record_fixes(
                "TXT", "@", "v=spf1 include:your-mail-provider.example -all"
            ),
        ),
    ),
    "dns.spf_weak": CheckText(
        title="SPF record doesn't say what to do with other senders",
        fix=Fix(
            what_it_means=(
                "Your SPF record ends with ?all, or has no all at the end, which means the "
                "same. That tells receiving mail servers to stay neutral about servers you "
                "haven't listed, so the record lists your senders but doesn't protect you."
            ),
            how_to_fix=(
                "End the record with ~all or -all. ~all marks other senders as suspicious and "
                "leaves the final decision to DMARC. -all tells receivers to reject them."
            ),
            platforms=dns_record_fixes(
                "TXT", "@", "v=spf1 include:your-mail-provider.example ~all"
            ),
        ),
    ),
    "dns.spf_softfail": CheckText(
        title="SPF uses ~all (soft fail)",
        fix=Fix(
            what_it_means=(
                "Your SPF record ends with ~all, so mail from servers you haven't listed is "
                "marked as suspicious rather than rejected outright. This is the setting most "
                "email providers recommend, and it doesn't lower your score. With an enforcing "
                "DMARC policy (quarantine or reject), the forged mail is still stopped."
            ),
            how_to_fix=(
                "Nothing is required. If DMARC isn't enforcing yet, fix that first, because it "
                "matters more. Once you're sure every service that sends as you is listed, you "
                "can switch to -all, which tells receivers to reject other senders outright."
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
    "dns.dmarc_monitoring_only": CheckText(
        title="DMARC is monitoring only: spoofed mail is still delivered",
        fix=Fix(
            what_it_means=(
                "Your DMARC policy is p=none, or has no valid policy and is treated that way. "
                "Receiving mail servers send you reports, but they still deliver email that "
                "fails your domain's checks. Against impersonation that protects no more than "
                "having no DMARC record, so it costs the same points."
            ),
            how_to_fix=(
                "p=none is a good first step: it lets you see who sends as you without "
                "blocking anything. Read the reports for a few weeks, fix any real service "
                "that fails, then change the policy to p=quarantine, and later to p=reject."
            ),
            platforms=dns_record_fixes(
                "TXT", "_dmarc", "v=DMARC1; p=quarantine; rua=mailto:you@example.com"
            ),
        ),
    ),
    "dns.dmarc_quarantine": CheckText(
        title="DMARC quarantines spoofed mail; reject is stronger",
        fix=Fix(
            what_it_means=(
                "Your DMARC policy is p=quarantine, so email that fails your domain's checks "
                "goes to spam. That is real protection and doesn't lower your score. Spoofed "
                "mail can still reach a spam folder, where someone may open it."
            ),
            how_to_fix=(
                "Once your reports show all your real email passes, change the policy to "
                "p=reject so receivers refuse the spoofed mail outright."
            ),
            platforms=dns_record_fixes(
                "TXT", "_dmarc", "v=DMARC1; p=reject; rua=mailto:you@example.com"
            ),
        ),
    ),
    "dns.dmarc_partial": CheckText(
        title="DMARC policy only applies to some mail",
        fix=Fix(
            what_it_means=(
                "Your DMARC record sets pct below 100, or t=y (testing). Receivers apply your "
                "policy to only that share of failing email, and treat the rest one step more "
                "gently: reject becomes quarantine, and quarantine becomes none."
            ),
            how_to_fix=(
                "A lower pct is a fine way to roll out a stricter policy. Once your reports "
                "look clean, remove pct (it defaults to 100) and any t=y tag."
            ),
            platforms=dns_record_fixes(
                "TXT", "_dmarc", "v=DMARC1; p=reject; rua=mailto:you@example.com"
            ),
        ),
    ),
    "dns.dmarc_subdomain_none": CheckText(
        title="DMARC doesn't protect your subdomains",
        fix=Fix(
            what_it_means=(
                "Your main DMARC policy is strict, but sp=none turns it off for subdomains. "
                "Anyone can send convincing fake email from addresses like "
                "billing.yourdomain.com, and it will still be delivered."
            ),
            how_to_fix=(
                "Remove the sp tag so subdomains follow your main policy, or set it to "
                "sp=quarantine or sp=reject. If a subdomain sends real email, give it its own "
                "DMARC record instead."
            ),
            platforms=dns_record_fixes(
                "TXT", "_dmarc", "v=DMARC1; p=reject; rua=mailto:you@example.com"
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
