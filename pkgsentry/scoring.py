"""Combine independent analyzer evidence into a review priority, not an automatic malware verdict."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from pkgsentry.analyzers.hooks import Hook
from pkgsentry.analyzers.obfuscation import Finding
from pkgsentry.analyzers.rules import Finding as CodeFinding
from pkgsentry.analyzers.typosquat import NameCheck
from pkgsentry.models import PackageInfo

_LEVELS = ((20, "low"), (40, "guarded"), (70, "high"), (101, "critical"))
_CODE_RULES = {"secret + network", "endpoint + network", "decoded exec"}
_OBFUSCATION_RULES = {
    "encoded code", "encoded exec", "encoded string", "string-built exec", "invisible unicode",
    "compiled-only module",
}


@dataclass(frozen=True)
class RiskSignal:
    category: str
    points: int
    strength: str
    context: str
    detail: str
    path: str = ""
    line: int = 0


@dataclass(frozen=True)
class RiskReport:
    score: int
    level: str
    signals: tuple[RiskSignal, ...]


def score_package(
    package: PackageInfo,
    name_check: NameCheck,
    hooks: list[Hook],
    findings: list[CodeFinding | Finding],
    now: datetime | None = None,
) -> RiskReport:
    """Score the strongest evidence per family; duplicate lines cannot inflate the score."""
    now = now or datetime.now(timezone.utc)
    candidates = _metadata_signals(package, now)
    candidates += _name_signals(name_check)
    candidates += _hook_signals(hooks)
    candidates += [_finding_signal(f) for f in findings if f.strength != "info"]

    strongest: dict[str, RiskSignal] = {}
    for signal in candidates:
        previous = strongest.get(signal.category)
        if previous is None or signal.points > previous.points:
            strongest[signal.category] = signal
    signals = list(strongest.values())

    code = strongest.get("code")
    install = strongest.get("install")
    bonus = _combination_bonus(install, code)
    if bonus:
        signals.append(bonus)
    score = min(100, sum(signal.points for signal in signals))
    level = next(label for boundary, label in _LEVELS if score < boundary)
    return RiskReport(score, level, tuple(sorted(signals, key=lambda s: (-s.points, s.category))))


@dataclass(frozen=True)
class _FindingSignal(RiskSignal):
    rule: str = ""


def _metadata_signals(package: PackageInfo, now: datetime) -> list[RiskSignal]:
    points = 0
    clues: list[str] = []
    if package.first_upload:
        uploaded = package.first_upload
        if uploaded.tzinfo is None:
            uploaded = uploaded.replace(tzinfo=timezone.utc)
        age = now - uploaded
        if timedelta(0) <= age <= timedelta(days=30):
            points += 5
            clues.append("first uploaded within 30 days")
    if package.release_count <= 1:
        points += 2
        clues.append("no published releases" if package.release_count == 0 else "only one release")
    if not package.homepage:
        points += 2
        clues.append("no homepage")
    if not package.summary:
        points += 2
        clues.append("empty summary")
    if package.description_length < 100:
        points += 1
        clues.append("very short description")
    if not package.author and not package.author_email:
        points += 1
        clues.append("no author details")
    points = min(points, 12)
    return [RiskSignal("metadata", points, "weak", "metadata", ", ".join(clues))] if points else []


def _name_signals(result: NameCheck) -> list[RiskSignal]:
    candidates = []
    if result.matches:
        match = result.matches[0]
        points = {"strong": 20, "medium": 12, "weak": 4}[match.strength]
        candidates.append(RiskSignal("name", points, match.strength, "name",
                                     f"{result.name} resembles {match.target.name}: {match.technique}"))
    if result.stdlib_module:
        candidates.append(RiskSignal("name", 8, "medium", "name", "name is a Python standard-library module"))
    return candidates


def _hook_signals(hooks: list[Hook]) -> list[RiskSignal]:
    candidates = []
    for hook in hooks:
        if hook.strength == "info":
            continue
        if hook.kind == "command-jacking":
            category, points = "command", 25 if hook.strength == "strong" else 12
        elif hook.kind in {".pth startup code", "startup module"}:
            category, points = "startup", {"strong": 20, "medium": 18, "weak": 6}.get(hook.strength, 0)
        elif hook.kind.startswith("custom ") or hook.kind == "unreadable setup.py":
            category = "install"
            points = {"strong": 24, "medium": 20, "weak": 5}.get(hook.strength, 0)
        elif "typosquat" in hook.kind or hook.kind == "uncommon build requirement":
            category = "dependency"
            points = {"strong": 16, "medium": 10, "weak": 3}.get(hook.strength, 0)
        else:
            continue
        if points:
            candidates.append(RiskSignal(category, points, hook.strength, hook.when, hook.detail, hook.path, hook.line))
    return candidates


def _finding_signal(finding: CodeFinding | Finding) -> _FindingSignal:
    obfuscation = finding.rule in _OBFUSCATION_RULES
    category = "obfuscation" if obfuscation else "code"
    if obfuscation:
        points = {"strong": 28, "medium": 14, "weak": 4}.get(finding.strength, 0)
    elif finding.rule == "secret + network":
        points = 30 if finding.context in {"install", "startup", "import"} else 20
    elif finding.rule == "endpoint + network":
        points = 26 if finding.context in {"install", "startup", "import"} else 16
    elif finding.rule == "decoded exec":
        points = 28 if finding.context in {"install", "startup", "import"} else 20
    elif finding.strength == "strong":
        points = 24 if finding.context in {"install", "startup", "import"} else 16
    elif finding.strength == "medium":
        points = 12 if finding.context in {"install", "startup", "import"} else 8
    else:
        points = 4 if finding.context in {"install", "startup", "import"} else 2
    return _FindingSignal(category, points, finding.strength, finding.context, finding.detail,
                          finding.path, finding.line, finding.rule)


def _combination_bonus(install: RiskSignal | None, code: RiskSignal | None) -> RiskSignal | None:
    if (install and isinstance(code, _FindingSignal) and install.category == "install" and code.rule == "secret + network"
            and code.context in {"install", "startup", "import"}):
        return RiskSignal("combination", 10, "strong", code.context,
                          "install-time code both replaces an install step and reads secrets before using the network")
    return None