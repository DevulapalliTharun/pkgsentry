"""The full static analysis of one unpacked package, in one place: the command line, the demo data and any watcher run the
same steps. Nothing here installs or runs the package."""

from dataclasses import dataclass
from pathlib import Path

from pkgsentry.analyzers.hooks import Hook, find_hooks
from pkgsentry.analyzers.obfuscation import scan_obfuscation
from pkgsentry.analyzers.rules import Finding, check_code
from pkgsentry.analyzers.typosquat import check_name
from pkgsentry.campaigns import Indicator, extract_indicators
from pkgsentry.fetch.pypi import validate_name
from pkgsentry.models import PackageInfo
from pkgsentry.scoring import RiskReport, score_package
from pkgsentry.triage.evidence import Excerpt, build_evidence


@dataclass(frozen=True)
class Analysis:
    hooks: list[Hook]
    findings: list[Finding]
    risk: RiskReport
    indicators: list[Indicator]
    excerpts: list[Excerpt]


def analyze(root: Path, package: PackageInfo, kind: str) -> Analysis:
    """kind is "sdist" or "wheel" (from PyPI, never from the archive layout)."""
    hooks = find_hooks(root, package.name, kind)
    findings = check_code(root, kind, hooks)
    findings.extend(scan_obfuscation(root, kind, hooks, findings))
    risk = score_package(package, check_name(validate_name(package.name)), hooks, findings)
    return Analysis(hooks, findings, risk, extract_indicators(root, findings), build_evidence(root, hooks, findings))
