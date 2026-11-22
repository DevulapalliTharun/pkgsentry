"""Check every claim in the model's answer against the evidence, then let verified answers move the level a little."""

import json
import re
from dataclasses import dataclass

from pkgsentry.triage.evidence import Excerpt
from pkgsentry.triage.prompt import IOC_TYPES, VERDICTS

LEVELS = ("low", "guarded", "high", "critical")
MAX_ITEMS = 20
MAX_TEXT = 400
MAX_SUMMARY = 1000
MIN_INDICATOR = 4
_TAG = re.compile(r"\[(C\d+)\]")


@dataclass(frozen=True)
class Behavior:
    description: str
    citations: tuple[str, ...]


@dataclass(frozen=True)
class Indicator:
    value: str
    kind: str
    found_in: tuple[str, ...]  # tags of the excerpts where the verifier itself found the value


@dataclass(frozen=True)
class Verified:
    verdict: str
    behaviors: tuple[Behavior, ...]
    indicators: tuple[Indicator, ...]
    summary: str
    dropped: tuple[str, ...]

    @property
    def supported(self) -> bool:
        return self.verdict in VERDICTS and bool(self.behaviors)


@dataclass(frozen=True)
class Decision:
    level: str
    reason: str


def verify(answer: str, excerpts: list[Excerpt]) -> Verified:
    """Keep only claims that cite real excerpts and indicators that appear in the excerpts word for word."""
    try:
        data = json.loads(answer)
    except ValueError:
        return Verified("invalid", (), (), "", ("the answer was not valid JSON",))
    if not isinstance(data, dict) or data.get("verdict") not in VERDICTS:
        return Verified("invalid", (), (), "", ("the answer had no valid verdict",))
    known = {excerpt.tag for excerpt in excerpts}
    dropped: list[str] = []

    behaviors = []
    for item in _items(data.get("behaviors")):
        description = _text(item.get("description"))
        cited = [_tag(c) for c in item.get("citations", []) if isinstance(c, str)] \
            if isinstance(item.get("citations"), list) else []
        valid = tuple(dict.fromkeys(c for c in cited if c in known))
        dropped += [f"citation {c} in a claim: no such excerpt" for c in dict.fromkeys(cited) if c not in known]
        if description and valid:
            behaviors.append(Behavior(description, valid))
        elif description:
            dropped.append(f"claim with no valid citation: {description[:80]}")

    indicators = []
    for item in _items(data.get("iocs")):
        value = item.get("value").strip() if isinstance(item.get("value"), str) else ""
        if not value or any(value == i.value for i in indicators):
            continue
        found = tuple(e.tag for e in excerpts if any(value in line for line in e.code))
        if MIN_INDICATOR <= len(value) <= MAX_TEXT and found:
            kind = item.get("type") if item.get("type") in IOC_TYPES else "other"
            indicators.append(Indicator(value, kind, found))
        else:
            dropped.append(f"indicator not found in the evidence: {value[:80]}")

    summary = _text(data.get("summary"), MAX_SUMMARY)
    tags = _TAG.findall(summary)
    if any(tag not in known for tag in tags):
        dropped.append("summary citations to missing excerpts: " + ", ".join(sorted({t for t in tags if t not in known})))
        summary = _TAG.sub(lambda m: m.group(0) if m.group(1) in known else "[?]", summary)
    if summary and not any(tag in known for tag in tags):
        dropped.append("summary with no valid citation")
        summary = ""
    return Verified(data["verdict"], tuple(behaviors), tuple(indicators), summary, tuple(dropped))


def decide(rule_level: str, verified: Verified, injection: bool) -> Decision:
    """The model can move a level by one band at most, never below a CRITICAL rule verdict, and never down when the
    evidence contains text aimed at AI reviewers. Unverified answers change nothing."""
    index = LEVELS.index(rule_level)
    if not verified.supported:
        return Decision(rule_level, "kept: the AI answer had no claim backed by a real excerpt")
    if verified.verdict == "malicious":
        if index == len(LEVELS) - 1:
            return Decision(rule_level, "the AI agrees: malicious")
        return Decision(LEVELS[index + 1], "raised one band: the AI found malicious behaviour in verified excerpts")
    if verified.verdict == "suspicious" or index == 0:
        return Decision(rule_level, f"kept: the AI says {verified.verdict}")
    if rule_level == "critical":
        return Decision(rule_level, "kept: the AI says benign, but CRITICAL is a floor it cannot lower; "
                                    "a human should look at the disagreement")
    if injection:
        return Decision(rule_level, "kept: the evidence contains text aimed at AI reviewers, so a benign answer "
                                    "is not trusted")
    return Decision(LEVELS[index - 1], "lowered one band: the AI explained the flagged lines as benign, "
                                       "citing verified excerpts")


def _items(value: object) -> list[dict]:
    return [item for item in value[:MAX_ITEMS] if isinstance(item, dict)] if isinstance(value, list) else []


def _text(value: object, limit: int = MAX_TEXT) -> str:
    return value.strip()[:limit] if isinstance(value, str) else ""


def _tag(citation: str) -> str:
    return citation.strip().strip("[]").strip().upper()
