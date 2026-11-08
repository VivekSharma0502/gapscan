"""Text for cookie checks."""

from app.checks.base import CheckText, Fix, Platform, PlatformFix
from app.checks.catalog._common import PlatformFixes

_NEXT_COOKIE = (
    "// Next.js route handler or server action\n"
    "(await cookies()).set('session', value, {\n"
    "  httpOnly: true,\n"
    "  secure: true,\n"
    "  sameSite: 'lax',\n"
    "  path: '/',\n"
    "})"
)

_EXPRESS_COOKIE = (
    "// Express\n"
    "res.cookie('session', value, {\n"
    "  httpOnly: true,\n"
    "  secure: true,\n"
    "  sameSite: 'lax',\n"
    "})"
)


def _cookie_fixes(nginx_flags: str) -> PlatformFixes:
    return {
        Platform.VERCEL: PlatformFix(
            instructions=(
                "Vercel doesn't change cookies, so set the flags where your app creates them."
            ),
            snippet=_NEXT_COOKIE,
        ),
        Platform.NETLIFY: PlatformFix(
            instructions=(
                "Netlify doesn't change cookies, so set the flags where your app or function "
                "creates them."
            ),
            snippet=_EXPRESS_COOKIE,
        ),
        Platform.NGINX: PlatformFix(
            instructions=(
                "Best fixed in your app. If nginx proxies to an app you can't change, add this "
                "to the proxied location (nginx 1.19.3 or newer), then reload nginx."
            ),
            snippet=f"proxy_cookie_flags {nginx_flags};",
        ),
        Platform.CLOUDFLARE: PlatformFix(
            instructions=(
                "Cloudflare has no simple setting for this. Set the flags where your app "
                "creates the cookie."
            ),
        ),
    }


TEXT: dict[str, CheckText] = {
    "cookies.secure": CheckText(
        title="Cookies can be sent without encryption",
        fix=Fix(
            what_it_means=(
                "These cookies don't have the Secure flag, so a browser may send them over "
                "plain HTTP, where someone on the same network could read them and take over "
                "a logged-in session."
            ),
            how_to_fix="Add the Secure flag to the cookies listed in the evidence.",
            platforms=_cookie_fixes("~ secure"),
        ),
    ),
    "cookies.httponly": CheckText(
        title="Login cookies can be read by scripts",
        fix=Fix(
            what_it_means=(
                "These look like login or session cookies, and they don't have the HttpOnly "
                "flag. If an attacker gets any script onto your page, it can read them and "
                "take over the account."
            ),
            how_to_fix=(
                "Add the HttpOnly flag to the cookies listed in the evidence. Only leave it "
                "off a cookie your own front-end code has to read."
            ),
            platforms=_cookie_fixes("session httponly"),
        ),
    ),
    "cookies.samesite": CheckText(
        title="Cookies have no safe SameSite setting",
        fix=Fix(
            what_it_means=(
                "SameSite controls whether cookies are sent with requests from other websites. "
                "Without a clear setting, browsers apply their own default, and a cookie with "
                "SameSite=None but no Secure flag is rejected outright."
            ),
            how_to_fix=(
                "Set SameSite=Lax on the cookies listed in the evidence. If a cookie really "
                "must work across sites, use SameSite=None together with Secure."
            ),
            platforms=_cookie_fixes("~ samesite=lax"),
        ),
    ),
}
