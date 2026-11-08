"""Text for TLS and HTTPS checks."""

from app.checks.base import CheckText, Fix, Platform, PlatformFix
from app.checks.catalog._common import PlatformFixes, header_fixes

_RENEW_CERT: PlatformFixes = {
    Platform.VERCEL: PlatformFix(
        instructions=(
            "Vercel renews certificates for you. Open Project Settings, then Domains, and fix "
            "any domain that does not show a valid configuration. Renewal fails while DNS is "
            "pointing somewhere else."
        ),
    ),
    Platform.NETLIFY: PlatformFix(
        instructions=(
            "Netlify renews certificates for you. Open Domain management, then HTTPS, check "
            "your DNS is verified, and use Renew certificate."
        ),
    ),
    Platform.NGINX: PlatformFix(
        instructions="If you use Let's Encrypt, renew and reload nginx.",
        snippet="sudo certbot renew\nsudo systemctl reload nginx",
    ),
    Platform.CLOUDFLARE: PlatformFix(
        instructions=(
            "Open SSL/TLS, then Edge Certificates, and check for an active certificate. With "
            "Full (strict) mode, the certificate on your own server must also be valid."
        ),
    ),
}

_INSTALL_CERT: PlatformFixes = {
    Platform.VERCEL: PlatformFix(
        instructions=(
            "Vercel issues a trusted certificate once your domain points at it. Open Project "
            "Settings, then Domains, and follow the DNS instructions shown there."
        ),
    ),
    Platform.NETLIFY: PlatformFix(
        instructions=(
            "Netlify issues a trusted certificate once your domain points at it. Open Domain "
            "management, then HTTPS, and choose Verify DNS configuration."
        ),
    ),
    Platform.NGINX: PlatformFix(
        instructions=(
            "Get a free certificate with certbot. If you manage files by hand, point nginx at "
            "fullchain.pem, because cert.pem alone leaves out the chain browsers need."
        ),
        snippet=(
            "sudo certbot --nginx -d example.com\n\n"
            "# or, in your server block:\n"
            "ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;\n"
            "ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;"
        ),
    ),
    Platform.CLOUDFLARE: PlatformFix(
        instructions=(
            "Make sure the DNS record is proxied (orange cloud). Then open SSL/TLS, set the "
            "mode to Full (strict), and check Edge Certificates shows an active certificate."
        ),
    ),
}

_HSTS_VALUE = "max-age=31536000"

_HSTS_FIXES: PlatformFixes = {
    **header_fixes("Strict-Transport-Security", _HSTS_VALUE),
    Platform.CLOUDFLARE: PlatformFix(
        instructions=(
            "Open SSL/TLS, then Edge Certificates, enable HTTP Strict Transport Security, and "
            "set Max Age to at least 6 months."
        ),
    ),
}

TEXT: dict[str, CheckText] = {
    "tls.no_https": CheckText(
        title="Site does not offer HTTPS",
        fix=Fix(
            what_it_means=(
                "Your site only works over plain HTTP, so anyone on the same network, such as "
                "public Wi-Fi, can read or change what your visitors see and send, including "
                "passwords. Browsers also label the site as Not Secure."
            ),
            how_to_fix="Install a free TLS certificate and serve the site over HTTPS.",
            platforms=_INSTALL_CERT,
        ),
    ),
    "tls.cert_expired": CheckText(
        title="TLS certificate has expired",
        fix=Fix(
            what_it_means=(
                "Your certificate's end date has passed. Visitors see a full-page browser "
                "warning, and most will leave. Attackers can also hide behind a warning that "
                "people have learned to click through."
            ),
            how_to_fix="Renew the certificate, then find out why automatic renewal stopped.",
            platforms=_RENEW_CERT,
        ),
    ),
    "tls.cert_untrusted": CheckText(
        title="TLS certificate is not trusted",
        fix=Fix(
            what_it_means=(
                "Browsers can't confirm this certificate really belongs to your site, so "
                "visitors see a security warning and their connection could be intercepted."
            ),
            how_to_fix=(
                "Use a certificate from a trusted authority that covers this exact domain, "
                "and make sure the server sends the full certificate chain."
            ),
            platforms=_INSTALL_CERT,
        ),
    ),
    "tls.cert_expiring": CheckText(
        title="TLS certificate expires soon",
        fix=Fix(
            what_it_means=(
                "Your certificate is close to its end date. Certificates that renew "
                "automatically usually do so well before this point, so renewal may be broken. "
                "If it lapses, visitors get a full-page browser warning."
            ),
            how_to_fix="Renew the certificate now and confirm automatic renewal is working.",
            platforms=_RENEW_CERT,
        ),
    ),
    "tls.legacy_version": CheckText(
        title="Server accepts outdated TLS versions",
        fix=Fix(
            what_it_means=(
                "Your server still agrees to TLS 1.0 or 1.1, which have known weaknesses and "
                "were retired in 2021. Modern browsers no longer use them, so turning them off "
                "removes the risk and rarely affects real visitors."
            ),
            how_to_fix="Allow only TLS 1.2 and TLS 1.3.",
            platforms={
                Platform.VERCEL: PlatformFix(
                    instructions=(
                        "Vercel manages TLS versions and there is no setting for this. If you "
                        "see this finding, check the domain really points at Vercel."
                    ),
                ),
                Platform.NETLIFY: PlatformFix(
                    instructions=(
                        "Netlify manages TLS versions and there is no setting for this. If you "
                        "see this finding, check the domain really points at Netlify."
                    ),
                ),
                Platform.NGINX: PlatformFix(
                    instructions="Set this in your http or server block, then reload nginx.",
                    snippet="ssl_protocols TLSv1.2 TLSv1.3;",
                ),
                Platform.CLOUDFLARE: PlatformFix(
                    instructions=(
                        "Open SSL/TLS, then Edge Certificates, and set Minimum TLS Version to "
                        "TLS 1.2."
                    ),
                ),
            },
        ),
    ),
    "tls.no_http_redirect": CheckText(
        title="HTTP does not redirect to HTTPS",
        fix=Fix(
            what_it_means=(
                "Someone who types your address or follows an old http:// link stays on an "
                "unencrypted connection, even though you have HTTPS available."
            ),
            how_to_fix="Permanently redirect every HTTP request to the HTTPS address.",
            platforms={
                Platform.VERCEL: PlatformFix(
                    instructions=(
                        "Vercel redirects to HTTPS automatically. If you see this finding, "
                        "check the domain really points at Vercel."
                    ),
                ),
                Platform.NETLIFY: PlatformFix(
                    instructions=(
                        "Netlify redirects to HTTPS automatically once a certificate is "
                        "active. Open Domain management, then HTTPS, to check it is."
                    ),
                ),
                Platform.NGINX: PlatformFix(
                    instructions="Add this server block, then reload nginx.",
                    snippet=(
                        "server {\n"
                        "    listen 80;\n"
                        "    server_name example.com;\n"
                        "    return 301 https://$host$request_uri;\n"
                        "}"
                    ),
                ),
                Platform.CLOUDFLARE: PlatformFix(
                    instructions=(
                        "Open SSL/TLS, then Edge Certificates, and turn on Always Use HTTPS."
                    ),
                ),
            },
        ),
    ),
    "tls.hsts_missing": CheckText(
        title="HSTS is not enabled",
        fix=Fix(
            what_it_means=(
                "HSTS tells browsers to always use HTTPS for your site. Without it, the first "
                "request on a hostile network can be downgraded to HTTP before your redirect "
                "ever happens."
            ),
            how_to_fix=(
                "Send the Strict-Transport-Security header on HTTPS responses. Make sure the "
                "whole site works over HTTPS first, because browsers will refuse HTTP until "
                "max-age runs out. Add includeSubDomains only if every subdomain has HTTPS."
            ),
            platforms=_HSTS_FIXES,
        ),
    ),
    "tls.hsts_weak": CheckText(
        title="HSTS lifetime is too short",
        fix=Fix(
            what_it_means=(
                "HSTS is on, but browsers forget it quickly, so returning visitors lose the "
                "protection soon after each visit."
            ),
            how_to_fix="Set max-age to at least six months. One year (31536000) is typical.",
            platforms=_HSTS_FIXES,
        ),
    ),
}
