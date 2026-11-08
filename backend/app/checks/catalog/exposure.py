"""Text for the active exposure checks, which run only on verified domains."""

from app.checks.base import CheckText, Fix, Platform, PlatformFix
from app.checks.catalog._common import PlatformFixes

# Security: excludes .well-known, which legitimately has to be public. Without the exception
# this rule would also block certificate renewal and domain verification.
_NGINX_DENY_DOTFILES = "location ~ /\\.(?!well-known) {\n    deny all;\n}"
_CLOUDFLARE_STEPS = "In Security, then WAF, create a custom rule with this expression and Block."


def _fixes(
    build_tool: str, nginx: tuple[str, str | None], cloudflare: tuple[str, str | None]
) -> PlatformFixes:
    """Vercel and Netlify only serve what a build outputs, so the fix there is the build."""
    return {
        Platform.VERCEL: PlatformFix(
            instructions=f"{build_tool} Then redeploy.",
        ),
        Platform.NETLIFY: PlatformFix(
            instructions=f"{build_tool} Then redeploy.",
        ),
        Platform.NGINX: PlatformFix(instructions=nginx[0], snippet=nginx[1]),
        Platform.CLOUDFLARE: PlatformFix(instructions=cloudflare[0], snippet=cloudflare[1]),
    }


TEXT: dict[str, CheckText] = {
    "exposure.env_file": CheckText(
        title="Environment file is publicly readable",
        fix=Fix(
            what_it_means=(
                "Anyone can download your .env file. These files usually hold database "
                "passwords and API keys, so treat every value in it as already stolen."
            ),
            how_to_fix=(
                "First change every password and key listed in the file, because blocking "
                "access doesn't undo a leak. Then move the file out of your public folder "
                "and block requests for it."
            ),
            platforms=_fixes(
                "Remove the file from your public or publish folder, and set these values "
                "as environment variables in the project settings.",
                ("Add this inside your server block, then reload nginx.", _NGINX_DENY_DOTFILES),
                (_CLOUDFLARE_STEPS, 'http.request.uri.path contains "/.env"'),
            ),
        ),
    ),
    "exposure.git_directory": CheckText(
        title="Git repository is publicly readable",
        fix=Fix(
            what_it_means=(
                "Your .git folder can be downloaded. Tools can rebuild your entire source "
                "code and its history from it, including any secret that was ever committed."
            ),
            how_to_fix=(
                "Deploy only your build output, not the whole repository, and block the .git "
                "folder. Change any secret that has ever been committed."
            ),
            platforms=_fixes(
                "Make sure your publish folder is your build output and not the repository root.",
                ("Add this inside your server block, then reload nginx.", _NGINX_DENY_DOTFILES),
                (_CLOUDFLARE_STEPS, 'http.request.uri.path contains "/.git"'),
            ),
        ),
    ),
    "exposure.ds_store": CheckText(
        title="macOS folder index file is public",
        fix=Fix(
            what_it_means=(
                "A .DS_Store file lists the names of the files in a folder. It shows attackers "
                "what else is there, including files you never linked to."
            ),
            how_to_fix=(
                "Delete .DS_Store from your site, add it to .gitignore, and block requests for it."
            ),
            platforms=_fixes(
                "Delete .DS_Store from your public or publish folder and add it to .gitignore.",
                ("Add this inside your server block, then reload nginx.", _NGINX_DENY_DOTFILES),
                (_CLOUDFLARE_STEPS, 'http.request.uri.path contains "/.DS_Store"'),
            ),
        ),
    ),
    "exposure.backup_file": CheckText(
        title="Backup file is publicly downloadable",
        fix=Fix(
            what_it_means=(
                "A backup or database dump can be downloaded by anyone. These often contain "
                "customer data, password hashes and configuration secrets."
            ),
            how_to_fix=(
                "Delete the file from your web root and keep backups somewhere private. If it "
                "held passwords or keys, change them, and consider whether customers' data "
                "was exposed."
            ),
            platforms=_fixes(
                "Remove the file from your public or publish folder.",
                (
                    "Delete the file. To block these file types too, add this inside your "
                    "server block, then reload nginx.",
                    "location ~* \\.(sql|bak|zip|tar\\.gz)$ {\n    deny all;\n}",
                ),
                (
                    _CLOUDFLARE_STEPS,
                    'ends_with(http.request.uri.path, ".sql") or '
                    'ends_with(http.request.uri.path, ".bak")',
                ),
            ),
        ),
    ),
    "exposure.source_maps": CheckText(
        title="JavaScript source maps are public",
        fix=Fix(
            what_it_means=(
                "Source maps let anyone read your original front-end code, with its comments "
                "and file structure. That makes bugs and hidden features easier to find."
            ),
            how_to_fix=(
                "Turn off public source maps in your build. If you need them for error "
                "tracking, upload them to that service privately instead."
            ),
            platforms=_fixes(
                "Turn off source maps in your build: productionBrowserSourceMaps: false in "
                "Next.js, or build.sourcemap: false in Vite.",
                (
                    "Add this inside your server block, then reload nginx.",
                    "location ~* \\.map$ {\n    deny all;\n}",
                ),
                (_CLOUDFLARE_STEPS, 'ends_with(http.request.uri.path, ".map")'),
            ),
        ),
    ),
    "exposure.directory_listing": CheckText(
        title="Directory listing is turned on",
        fix=Fix(
            what_it_means=(
                "Visiting a folder shows every file in it. Anyone can browse for files you "
                "didn't mean to publish."
            ),
            how_to_fix=(
                "Turn off directory listing on your web server, and check the listed folders "
                "for anything that shouldn't be public."
            ),
            platforms=_fixes(
                "This platform doesn't list folders by itself, so the listing comes from your "
                "app or a function. Remove the route that generates it.",
                (
                    "Remove any autoindex on line, or set this, then reload nginx.",
                    "autoindex off;",
                ),
                (
                    "Cloudflare can't turn this off. Fix it on the web server behind Cloudflare.",
                    None,
                ),
            ),
        ),
    ),
}
