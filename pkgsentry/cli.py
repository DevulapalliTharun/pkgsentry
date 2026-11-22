"""Command line: `pkgsentry info` and `pkgsentry fetch`."""

import argparse
import shutil
import sys
from datetime import datetime
from pathlib import Path

from pkgsentry.fetch.download import download_file
from pkgsentry.fetch.extract import ExtractionError, ExtractionReport, safe_extract
from pkgsentry.fetch.pypi import PyPIError, get_package_info, validate_name, validate_version
from pkgsentry.models import PackageInfo, ReleaseFile


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pkgsentry",
        description="Inspect Python packages for malicious behaviour without installing them.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    info = commands.add_parser("info", help="show what PyPI knows about a package")
    info.add_argument("name", help="package name, for example: requests")
    info.add_argument("--version", help="a specific version (default: latest)")
    fetch = commands.add_parser(
        "fetch", help="download a package file, verify its SHA-256 and unpack it safely (never installs or runs it)"
    )
    fetch.add_argument("name", help="package name, for example: requests")
    fetch.add_argument("--version", help="a specific version (default: latest)")
    fetch.add_argument("--kind", choices=["sdist", "wheel"], default="sdist",
                       help="which file to fetch (default: sdist, where install-time code lives)")
    fetch.add_argument("--dest", type=Path, default=Path("downloads"), help="download folder (default: downloads/)")
    args = parser.parse_args(argv)

    try:
        if args.command == "info":
            print(format_info(get_package_info(args.name, args.version)))
        elif args.command == "fetch":
            print(_fetch(args))
    except (PyPIError, ExtractionError, ValueError) as error:
        print(f"error: {_printable(str(error))}", file=sys.stderr)
        return 1
    return 0


def _fetch(args: argparse.Namespace) -> str:
    package = get_package_info(args.name, args.version)
    file = next((f for f in package.files if f.kind == args.kind), None)
    if file is None:
        raise PyPIError(f"{package.name} {package.version} has no {args.kind} file")
    # The folder name comes from PyPI metadata, so it is validated like user input.
    folder = args.dest / f"{validate_name(package.name)}-{validate_version(package.version)}"
    archive = download_file(file, folder)
    extracted = folder / file.kind
    shutil.rmtree(extracted, ignore_errors=True)
    return format_fetch(file, archive, safe_extract(archive, extracted))


def format_info(package: PackageInfo) -> str:
    lines = [
        f"{_printable(package.name)} {_printable(package.version)}",
        f"  Summary:       {_printable(package.summary) or '(empty)'}",
        f"  Author:        {_printable(package.author or package.author_email) or '(none)'}",
        f"  Homepage:      {_printable(package.homepage) or '(none)'}",
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


def format_fetch(file: ReleaseFile, archive: Path, report: ExtractionReport) -> str:
    lines = [
        f"Downloaded  {_short(archive)}  ({file.size / 1024:.1f} KB)",
        f"SHA-256     {file.sha256[:16]}...  matches PyPI",
        f"Unpacked    {len(report.files)} files, {report.bytes_written / 1024:.1f} KB  ->  {_short(report.root)}",
    ]
    if report.skipped:
        lines.append(f"Refused     {len(report.skipped)} suspicious entries:")
        lines += [f"              {_printable(name)}  ({reason})" for name, reason in report.skipped]
    else:
        lines.append("Refused     nothing (no links, path tricks or duplicates)")
    shown = sorted(report.files)
    lines.append("Files:")
    lines += [f"  {_printable(name)}" for name in shown[:15]]
    if len(shown) > 15:
        lines.append(f"  ... and {len(shown) - 15} more")
    lines.append("Nothing was installed or run.")
    return "\n".join(lines)


def _printable(text: str) -> str:
    # Names and metadata are attacker-controlled; raw control characters could rewrite the terminal.
    return "".join(ch if ch.isprintable() else "?" for ch in text)


def _short(path: Path) -> str:
    path = path.resolve()
    cwd = Path.cwd().resolve()
    return str(path.relative_to(cwd)) if path.is_relative_to(cwd) else str(path)


def _day(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%d") if value else "unknown"
