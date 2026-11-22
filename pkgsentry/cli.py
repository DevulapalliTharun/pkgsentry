"""Command line: `pkgsentry info`, `fetch`, `check-name`, `hooks`, `code` and `scan` (with optional `--ai`)."""

import argparse
import re
import shutil
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

from pkgsentry.analyzers.hooks import Hook, find_hooks
from pkgsentry.analyzers.obfuscation import scan_obfuscation
from pkgsentry.analyzers.rules import Finding, check_code
from pkgsentry.analyzers.typosquat import NameCheck, check_name
from pkgsentry.fetch.download import download_file
from pkgsentry.fetch.extract import ExtractionError, ExtractionReport, safe_extract
from pkgsentry.fetch.pypi import PyPIError, get_package_info, validate_name, validate_version
from pkgsentry.models import PackageInfo, ReleaseFile
from pkgsentry.scoring import RiskReport, score_package
from pkgsentry.triage.evidence import Excerpt, build_evidence
from pkgsentry.triage.gemini import MODEL, GeminiError, generate_json, load_api_key
from pkgsentry.triage.prompt import SCHEMA, SYSTEM, build_prompt
from pkgsentry.triage.verify import Decision, Verified, decide, verify

_URL_TEXT = re.compile(r"(?i)\bhttp(s?)://([^\s/'\"<>]+)")
_IPV4_TEXT = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")


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
    commands.add_parser("code", parents=[download],
                        help="fetch a package and report what its code does, weighted by when it runs (never runs it)")
    scan = commands.add_parser("scan", parents=[download],
                               help="run all current checks and print a risk score with evidence (never installs or runs it)")
    scan.add_argument("--ai", action="store_true",
                      help="if the score is above LOW, ask Gemini to explain the flagged lines; every claim is verified")
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
        elif args.command == "code":
            package, file, _, report = _fetch(args)
            label = f"{package.name} {package.version} ({file.kind})"
            hooks = find_hooks(report.root, package.name, file.kind)
            findings = check_code(report.root, file.kind, hooks)
            findings.extend(scan_obfuscation(report.root, file.kind, hooks, findings))
            print(format_code(label, findings))
        elif args.command == "scan":
            package, file, archive, extraction = _fetch(args)
            hooks = find_hooks(extraction.root, package.name, file.kind)
            name_check = check_name(validate_name(package.name))
            findings = check_code(extraction.root, file.kind, hooks)
            findings.extend(scan_obfuscation(extraction.root, file.kind, hooks, findings))
            result = score_package(package, name_check, hooks, findings)
            print(format_scan(package, file, archive, extraction, result))
            if args.ai:
                label = f"{package.name} {package.version} ({file.kind})"
                print()
                print(_triage(label, extraction.root, hooks, findings, result))
        elif args.command == "check-name":
            checks = [check_name(validate_name(name)) for name in args.names]
            print("\n\n".join(format_name_check(result) for result in checks))
    except (PyPIError, ExtractionError, GeminiError, ValueError) as error:
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


def format_code(label: str, findings: list[Finding]) -> str:
    counts = Counter(f.strength for f in findings)
    summary = ", ".join(f"{counts[s]} {s}" for s in ("strong", "medium", "weak", "info") if counts[s])
    lines = [f"{_printable(label)}: what the code does ({summary or 'nothing found'})"]
    for f in findings:
        if f.strength == "info":
            continue
        lines.append(f"  {f.strength:<6}  {f.context:<7}  {_printable(f.path)}:{f.line}")
        lines.append(f"          {f.rule}: {_printable(_defang(f.detail))}")
        if f.evidence:
            lines.append(f"          > {_printable(_defang(f.evidence))}")
    if counts["info"]:
        lines.append(f"  {counts['info']} info findings not shown: normal inside functions, tests or docs")
    lines.append("Nothing was installed or run.")
    return "\n".join(lines)


def format_scan(package: PackageInfo, file: ReleaseFile, archive: Path,
                extraction: ExtractionReport, result: RiskReport) -> str:
    lines = [
        f"{_printable(package.name)} {_printable(package.version)} ({file.kind})",
        f"Risk score  {result.score}/100  {_level(result.level)}",
        f"Source      {_short(archive)}  SHA-256 verified; {len(extraction.files)} files unpacked safely",
        "Evidence:",
    ]
    if result.signals:
        for signal in result.signals:
            where = f"  {_printable(signal.path)}:{signal.line}" if signal.path else ""
            lines.append(f"  +{signal.points:>2}  {signal.category:<14} {signal.context:<8} "
                         f"{signal.strength:<6} {_printable(_defang(signal.detail))}{where}")
    else:
        lines.append("  No risk signals found in the selected file.")
    lines.append("This is a triage score, not a malware verdict.")
    lines.append("Nothing was installed or run.")
    return "\n".join(lines)


def _triage(label: str, root: Path, hooks: list[Hook], findings: list[Finding], result: RiskReport) -> str:
    if result.level == "low":
        return "AI triage   skipped: the rule score is LOW, and the AI only reviews flagged packages"
    excerpts = build_evidence(root, hooks, findings)
    if not excerpts:
        return "AI triage   skipped: the rules flagged no code lines to show the AI"
    answer, tokens = generate_json(SYSTEM, build_prompt(label, hooks, findings, excerpts), SCHEMA, load_api_key())
    verified = verify(answer, excerpts)
    return format_triage(excerpts, verified, decide(result.level, verified, any(e.injection for e in excerpts)),
                         tokens)


def format_triage(excerpts: list[Excerpt], verified: Verified, decision: Decision, tokens: int) -> str:
    # The model's text is untrusted too: it may repeat attacker strings, so it is printed like package data.
    shown = "1 excerpt (C1)" if len(excerpts) == 1 else f"{len(excerpts)} excerpts (C1-C{len(excerpts)})"
    lines = [
        f"AI triage   {MODEL} read {shown}, {tokens:,} tokens",
        f"AI verdict  {verified.verdict}",
        f"Final level {_level(decision.level)}: {decision.reason}",
    ]
    if verified.behaviors:
        lines.append("Behaviours (each cites an excerpt that exists):")
        lines += [f"  [{', '.join(b.citations)}] {_printable(_defang(b.description))}" for b in verified.behaviors]
    if verified.indicators:
        lines.append("Indicators (each found word for word in the excerpts):")
        for indicator in verified.indicators:
            value = _defang(indicator.value)
            if indicator.kind == "domain":
                value = value.replace(".", "[.]")
            lines.append(f"  {indicator.kind:<9} {_printable(value)}  [{', '.join(indicator.found_in)}]")
    if verified.summary:
        lines.append(f"Summary     {_printable(_defang(verified.summary))}")
    for note in verified.dropped[:6]:
        lines.append(f"Verifier    dropped {_printable(_defang(note))}")
    if len(verified.dropped) > 6:
        lines.append(f"Verifier    ... and {len(verified.dropped) - 6} more dropped items")
    aimed = [e.tag for e in excerpts if e.injection]
    if aimed:
        lines.append(f"Warning     text aimed at AI reviewers in {', '.join(aimed)}: possible prompt injection")
    lines.append("The AI saw only these excerpts. It could not run code, and it cannot change the rule score.")
    return "\n".join(lines)


def _level(value: str) -> str:
    return {"low": "LOW", "guarded": "GUARDED", "high": "HIGH", "critical": "CRITICAL"}.get(value, value.upper())


def _printable(text: str) -> str:
    # Names and metadata are attacker-controlled; raw control characters could rewrite the terminal.
    return "".join(ch if ch.isprintable() else "?" for ch in text)


def _defang(text: str) -> str:
    """Indicators in reports must not be clickable: hxxps://evil[.]example, 203[.]0[.]113[.]5."""
    text = _URL_TEXT.sub(lambda m: f"hxxp{m.group(1)}://{m.group(2).replace('.', '[.]')}", text)
    return _IPV4_TEXT.sub(lambda m: "[.]".join(m.groups()), text)


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
