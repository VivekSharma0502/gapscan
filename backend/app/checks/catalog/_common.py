"""Builders for fixes that have the same shape across many checks."""

import json

from app.checks.base import Platform, PlatformFix

PlatformFixes = dict[Platform, PlatformFix]


def dns_record_fixes(record_type: str, name: str, value: str, note: str = "") -> PlatformFixes:
    """How to add one DNS record. DNS lives wherever the domain's nameservers point."""
    record = f"Type: {record_type}\nName: {name}\nValue: {value}"
    if note:
        record = f"{record}\n\n{note}"
    return {
        Platform.VERCEL: PlatformFix(
            instructions=(
                "If Vercel hosts your DNS, add this record on your domain's page in the Vercel "
                "dashboard. Otherwise add it wherever your DNS is managed."
            ),
            snippet=record,
        ),
        Platform.NETLIFY: PlatformFix(
            instructions=(
                "If Netlify hosts your DNS, add this record under Domain management. Otherwise "
                "add it wherever your DNS is managed."
            ),
            snippet=record,
        ),
        Platform.NGINX: PlatformFix(
            instructions=(
                "nginx doesn't control DNS, so there is nothing to change here. Add the record "
                "described above at your DNS provider."
            ),
        ),
        Platform.CLOUDFLARE: PlatformFix(
            instructions="Open DNS, then Records, and add this record.",
            snippet=record,
        ),
    }


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
