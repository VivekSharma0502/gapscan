"""Text for CMS checks."""

from app.checks.base import CheckText, Fix, Platform, PlatformFix

_APPLY_IN_WORDPRESS = "Apply the steps above in WordPress itself."

TEXT: dict[str, CheckText] = {
    "cms.wordpress_version": CheckText(
        title="WordPress version is publicly visible",
        fix=Fix(
            what_it_means=(
                "Your homepage announces which version of WordPress you run. Attackers scan "
                "for sites on versions with known bugs, so this makes you easy to match if you "
                "ever fall behind on updates."
            ),
            how_to_fix=(
                "Open Dashboard, then Updates, install the latest version, and turn on "
                "automatic updates. To stop showing the version, add this to your theme's "
                "functions.php: remove_action('wp_head', 'wp_generator');"
            ),
            platforms={
                Platform.VERCEL: PlatformFix(
                    instructions=f"Vercel has no setting for this. {_APPLY_IN_WORDPRESS}",
                ),
                Platform.NETLIFY: PlatformFix(
                    instructions=f"Netlify has no setting for this. {_APPLY_IN_WORDPRESS}",
                ),
                Platform.NGINX: PlatformFix(
                    instructions=f"nginx has no simple setting for this. {_APPLY_IN_WORDPRESS}",
                ),
                Platform.CLOUDFLARE: PlatformFix(
                    instructions=f"Cloudflare has no setting for this. {_APPLY_IN_WORDPRESS}",
                ),
            },
        ),
    ),
}
