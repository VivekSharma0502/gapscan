"""Builders for fixes that have the same shape across many checks."""

import json

from app.checks.base import Platform, PlatformFix

PlatformFixes = dict[Platform, PlatformFix]


def header_fixes(name: str, value: str) -> PlatformFixes:
    """How to set one response header on each platform."""
    vercel_config = {
        "headers": [{"source": "/(.*)", "headers": [{"key": name, "value": value}]}],
    }
    return {
        Platform.VERCEL: PlatformFix(
            instructions="Add this to vercel.json in your project root, then redeploy.",
            snippet=json.dumps(vercel_config, indent=2),
        ),
        Platform.NETLIFY: PlatformFix(
            instructions="Add this to a file named _headers in your publish folder, then redeploy.",
            snippet=f"/*\n  {name}: {value}",
        ),
        Platform.NGINX: PlatformFix(
            instructions=(
                "Add this inside your server block, then reload nginx. If a location block has "
                "its own add_header lines, repeat this there, because nginx does not merge them."
            ),
            snippet=f'add_header {name} "{value}" always;',
        ),
        Platform.CLOUDFLARE: PlatformFix(
            instructions=(
                "In the dashboard, open Rules, create a Response Header Transform Rule that "
                "applies to all incoming requests, and add this operation."
            ),
            snippet=f"Operation: Set static\nHeader name: {name}\nValue: {value}",
        ),
    }
