"""Command line: `pkgsentry info <package> [--version X]`."""

import argparse
import sys
from datetime import datetime

from pkgsentry.fetch.pypi import PyPIError, get_package_info
from pkgsentry.models import PackageInfo


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pkgsentry",
        description="Inspect Python packages for malicious behaviour without installing them.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    info = commands.add_parser("info", help="show what PyPI knows about a package")
    info.add_argument("name", help="package name, for example: requests")
    info.add_argument("--version", help="a specific version (default: latest)")
    args = parser.parse_args(argv)

    if args.command == "info":
        try:
            package = get_package_info(args.name, args.version)
        except (PyPIError, ValueError) as error:
            print(f"error: {error}", file=sys.stderr)
            return 1
        print(format_info(package))
    return 0


def format_info(package: PackageInfo) -> str:
    lines = [
        f"{package.name} {package.version}",
        f"  Summary:       {package.summary or '(empty)'}",
        f"  Author:        {package.author or package.author_email or '(none)'}",
        f"  Homepage:      {package.homepage or '(none)'}",
        f"  Description:   {package.description_length:,} characters",
        f"  Releases:      {package.release_count} (first upload {_day(package.first_upload)})",
        f"  This version:  uploaded {_day(package.uploaded)}",
        "  Files:",
    ]
    width = max((len(f.filename) for f in package.files), default=0)
    for f in package.files:
        lines.append(f"    {f.kind:<6} {f.filename:<{width}}  {f.size / 1024:>9.1f} KB  sha256 {f.sha256[:12]}...")
    if not package.files:
        lines.append("    (none)")
    return "\n".join(lines)


def _day(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%d") if value else "unknown"
