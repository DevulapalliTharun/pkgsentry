"""Command line: `pkgsentry info`, `fetch`, `check-name` and `hooks`."""

import argparse
import shutil
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

from pkgsentry.analyzers.hooks import Hook, find_hooks
from pkgsentry.analyzers.typosquat import NameCheck, check_name
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
    download = argparse.ArgumentParser(add_help=False)
    download.add_argument("name", help="package name, for example: requests")
    download.add_argument("--version", help="a specific version (default: latest)")
    download.add_argument("--kind", choices=["sdist", "wheel"], default="sdist",
                          help="which file to fetch (default: sdist, where install-time code lives)")
    download.add_argument("--dest", type=Path, default=Path("downloads"), help="download folder (default: downloads/)")
    commands.add_parser("fetch", parents=[download],
                        help="download a package file, verify its SHA-256 and unpack it safely (never installs or runs it)")
    commands.add_parser("hooks", parents=[download],
                        help="fetch a package and list code that can run without being called (never installs or runs it)")
    check = commands.add_parser(
        "check-name", help="does a name imitate a popular package? (compares names only, downloads nothing)"
    )
    check.add_argument("names", nargs="+", metavar="name", help="one or more package names")
    args = parser.parse_args(argv)

    try:
        if args.command == "info":
            print(format_info(get_package_info(args.name, args.version)))
        elif args.command == "fetch":
            _, file, archive, report = _fetch(args)
            print(format_fetch(file, archive, report))
        elif args.command == "hooks":
            package, file, _, report = _fetch(args)
            label = f"{package.name} {package.version} ({file.kind})"
            print(format_hooks(label, find_hooks(report.root, package.name, file.kind)))
        elif args.command == "check-name":
            checks = [check_name(validate_name(name)) for name in args.names]
            print("\n\n".join(format_name_check(result) for result in checks))
    except (PyPIError, ExtractionError, ValueError) as error:
        print(f"error: {_printable(str(error))}", file=sys.stderr)
        return 1
    return 0


def _fetch(args: argparse.Namespace) -> tuple[PackageInfo, ReleaseFile, Path, ExtractionReport]:
    package = get_package_info(args.name, args.version)
    file = next((f for f in package.files if f.kind == args.kind), None)
    if file is None:
        raise PyPIError(f"{package.name} {package.version} has no {args.kind} file")
    # The folder name comes from PyPI metadata, so it is validated like user input.
    folder = args.dest / f"{validate_name(package.name)}-{validate_version(package.version)}"
    archive = download_file(file, folder)
    extracted = folder / file.kind
    shutil.rmtree(extracted, ignore_errors=True)
    return package, file, archive, safe_extract(archive, extracted)


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


def format_name_check(result: NameCheck) -> str:
    lines = [f"{_printable(result.name)}  (PyPI reads it as: {_printable(result.normalized)})"]
    if result.popular:
        top = result.popular
        lines.append(f"  A popular package itself: #{top.rank:,}, {_count(top.downloads)} downloads in 30 days.")
    elif result.matches:
        lines.append("  Looks like:")
        width = max(len(m.target.name) for m in result.matches)
        for m in result.matches:
            lines.append(
                f"    {m.strength:<6}  {m.target.name:<{width}}  #{m.target.rank:<6,}"
                f"{_count(m.target.downloads):>7} downloads  {m.technique}"
            )
    else:
        lines.append("  No popular package looks like this name.")
    if result.stdlib_module:
        lines.append("  Also a Python standard-library module name: people may pip install it by mistake.")
    return "\n".join(lines)


def format_hooks(label: str, hooks: list[Hook]) -> str:
    counts = Counter(h.strength for h in hooks)
    summary = ", ".join(f"{counts[s]} {s}" for s in ("strong", "medium", "weak", "info") if counts[s])
    lines = [f"{_printable(label)}: code that can run without being called" + (f" ({summary})" if hooks else "")]
    for h in hooks:
        where = f"{h.path}:{h.line}" if h.line else h.path
        lines.append(f"  {h.strength:<6}  {h.when:<16}  {_printable(where)}")
        lines.append(f"          {_printable(h.kind)}: {_printable(h.detail)}")
    if not hooks:
        lines.append("  None found: no setup.py, build hooks, startup files or command names.")
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


def _count(number: int) -> str:
    for size, unit in ((10**9, "B"), (10**6, "M"), (10**3, "K")):
        if number >= size:
            return f"{number / size:.1f}{unit}"
    return str(number)
