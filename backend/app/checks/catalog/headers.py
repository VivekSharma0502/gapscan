"""Text for HTTP security header checks."""

from app.checks.base import CheckText, Fix, Platform, PlatformFix
from app.checks.catalog._common import header_fixes

_STARTER_CSP = (
    "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
    "object-src 'none'; base-uri 'self'; form-action 'self'"
)

_CSP_ROLLOUT_NOTE = (
    "Start with this policy under the header name Content-Security-Policy-Report-Only, watch "
    "the browser console for anything it would block, add the domains you really use, and "
    "then switch to the enforcing header."
)

TEXT: dict[str, CheckText] = {
    "headers.csp_missing": CheckText(
        title="Content Security Policy is missing",
        fix=Fix(
            what_it_means=(
                "A Content Security Policy tells browsers which scripts are allowed to run. "
                "Without one, a single injection bug lets an attacker run their own code in "
                "your visitors' browsers and steal their sessions or data."
            ),
            how_to_fix=f"Add a Content-Security-Policy header. {_CSP_ROLLOUT_NOTE}",
            platforms=header_fixes("Content-Security-Policy", _STARTER_CSP),
        ),
    ),
    "headers.csp_weak": CheckText(
        title="Content Security Policy is too permissive",
        fix=Fix(
            what_it_means=(
                "You have a Content Security Policy, but it still allows the kinds of script "
                "attackers rely on, so it gives much less protection than it appears to."
            ),
            how_to_fix=(
                "Remove the sources listed in the evidence from script-src and default-src. "
                "For inline scripts, use a per-response nonce or a hash instead of "
                f"'unsafe-inline'. {_CSP_ROLLOUT_NOTE}"
            ),
            platforms=header_fixes("Content-Security-Policy", _STARTER_CSP),
        ),
    ),
    "headers.clickjacking": CheckText(
        title="Site can be embedded by other websites",
        fix=Fix(
            what_it_means=(
                "Another website can load your pages in an invisible frame and trick your "
                "visitors into clicking buttons they can't see, such as confirming a payment "
                "or changing a setting. This is called clickjacking."
            ),
            how_to_fix=(
                "Send X-Frame-Options, or add frame-ancestors to your Content Security Policy. "
                "If you also use frame-ancestors, browsers follow that and ignore this header."
            ),
            platforms=header_fixes("X-Frame-Options", "SAMEORIGIN"),
        ),
    ),
    "headers.content_type_options": CheckText(
        title="X-Content-Type-Options is not set",
        fix=Fix(
            what_it_means=(
                "Browsers may guess what a file is instead of trusting your server. A file "
                "uploaded as an image could then be treated as a script."
            ),
            how_to_fix="Send X-Content-Type-Options: nosniff on every response.",
            platforms=header_fixes("X-Content-Type-Options", "nosniff"),
        ),
    ),
    "headers.referrer_policy": CheckText(
        title="Referrer-Policy is missing or leaks full URLs",
        fix=Fix(
            what_it_means=(
                "When visitors click a link to another site, that site can be told the full "
                "address they came from, including any private tokens or IDs in the URL."
            ),
            how_to_fix="Send Referrer-Policy: strict-origin-when-cross-origin.",
            platforms=header_fixes("Referrer-Policy", "strict-origin-when-cross-origin"),
        ),
    ),
    "headers.permissions_policy": CheckText(
        title="Permissions-Policy is not set",
        fix=Fix(
            what_it_means=(
                "This optional header turns off browser features your site doesn't use, such "
                "as the camera or microphone, so injected or third-party code can't ask for "
                "them. It is extra hardening and does not lower your score."
            ),
            how_to_fix=(
                "Send a Permissions-Policy that disables what you don't use. Remove any "
                "feature from this example that your site needs."
            ),
            platforms=header_fixes(
                "Permissions-Policy", "camera=(), microphone=(), geolocation=()"
            ),
        ),
    ),
    "headers.server_version": CheckText(
        title="Server reveals its software version",
        fix=Fix(
            what_it_means=(
                "Your responses announce exactly which software version you run, so anyone can "
                "look up known bugs for that version. Hiding it doesn't fix those bugs, but it "
                "stops you being an easy match for automated attacks."
            ),
            how_to_fix=(
                "Remove the version from the header shown in the evidence, and keep that "
                "software up to date. In Express, call app.disable('x-powered-by'). In PHP, "
                "set expose_php = Off."
            ),
            platforms={
                Platform.VERCEL: PlatformFix(
                    instructions=(
                        "Vercel's own headers don't include versions, so this one comes from "
                        "your app. Turn it off there, as described above."
                    ),
                ),
                Platform.NETLIFY: PlatformFix(
                    instructions=(
                        "Netlify's own headers don't include versions, so this one comes from "
                        "your app or function. Turn it off there, as described above."
                    ),
                ),
                Platform.NGINX: PlatformFix(
                    instructions=(
                        "Hide nginx's version and any header added by the app behind it, then "
                        "reload nginx."
                    ),
                    snippet="server_tokens off;\nproxy_hide_header X-Powered-By;",
                ),
                Platform.CLOUDFLARE: PlatformFix(
                    instructions=(
                        "Create a Response Header Transform Rule under Rules and add this "
                        "operation, once for each header shown in the evidence."
                    ),
                    snippet="Operation: Remove\nHeader name: X-Powered-By",
                ),
            },
        ),
    ),
}
