"""The evidence pack: numbered excerpts around the lines the rules flagged. It is all the model sees of a package."""

import re
from dataclasses import dataclass, replace
from pathlib import Path

from pkgsentry.analyzers.hooks import Hook
from pkgsentry.analyzers.rules import Finding
from pkgsentry.analyzers.source import read_source, read_text

CONTEXT_LINES = 2
MAX_EXCERPTS = 12
MAX_LINE_CHARS = 200
MAX_EVIDENCE_CHARS = 12_000
_ORDER = {"strong": 0, "medium": 1, "weak": 2}
# Text that speaks to an AI reviewer. Paraphrases get past any pattern, so this is a warning sign, not the defence.
_INJECTION = re.compile(
    r"(?i)\b(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:of\s+)?(?:the\s+|your\s+|any\s+)?"
    r"(?:previous|prior|above|earlier|preceding)\s+(?:instructions?|prompts?|messages?|rules)\b"
    r"|\bforget\s+everything\b"
    r"|\b(?:mark|classify|label|report|treat|consider|rate)\b[^\n]{0,40}?\bas\s+"
    r"(?:safe|benign|harmless|legit(?:imate)?|clean|not\s+malicious)\b"
    r"|\bthis\s+(?:code|package|file|script|module|library)\s+is\s+"
    r"(?:safe|benign|harmless|legit(?:imate)?|clean|not\s+malicious)\b"
)


@dataclass(frozen=True)
class Excerpt:
    tag: str
    path: str
    start: int
    code: tuple[str, ...]  # the lines exactly as the model sees them: escaped and shortened
    cut: tuple[int, ...]  # characters left out at the end of each line
    flagged: tuple[int, ...]
    rules: tuple[str, ...]

    @property
    def injection(self) -> bool:
        return any(_INJECTION.search(line) for line in self.code)

    def render(self) -> str:
        end = self.start + len(self.code) - 1
        header = (f"[{self.tag}] {visible(self.path)} lines {self.start}-{end} "
                  f"(flagged line {', '.join(map(str, self.flagged))}: {', '.join(self.rules)})")
        body = [f"{'>' if number in self.flagged else ' '}{number:>5} | {text}"
                + (f" ...[{cut} more characters]" if cut else "")
                for number, (text, cut) in enumerate(zip(self.code, self.cut), self.start)]
        return "\n".join([header, *body])


def build_evidence(root: Path, hooks: list[Hook], findings: list[Finding]) -> list[Excerpt]:
    """Excerpts around every non-info hook and finding line, strongest first, within fixed size limits."""
    marks: dict[str, dict[int, tuple[int, set[str]]]] = {}
    for path, line, strength, rule in ([(h.path, h.line, h.strength, h.kind) for h in hooks]
                                       + [(f.path, f.line, f.strength, f.rule) for f in findings]):
        if line > 0 and strength in _ORDER:
            order, rules = marks.setdefault(path, {}).get(line, (len(_ORDER), set()))
            marks[path][line] = (min(order, _ORDER[strength]), rules | {visible(rule)})

    candidates: list[tuple[int, Excerpt]] = []
    for path, lines in marks.items():
        try:
            text = _read_lines(root / path)
        except OSError:
            continue
        group: list[int] = []
        for line in sorted(n for n in lines if n <= len(text)):
            if group and line - group[-1] > 2 * CONTEXT_LINES + 1:  # windows would neither overlap nor touch
                candidates.append(_window(path, text, group, lines))
                group = []
            group.append(line)
        if group:
            candidates.append(_window(path, text, group, lines))

    chosen: list[Excerpt] = []
    size = 0
    for _, excerpt in sorted(candidates, key=lambda c: (c[0], c[1].path, c[1].start)):
        excerpt = replace(excerpt, tag=f"C{len(chosen) + 1}")
        cost = len(excerpt.render())
        if len(chosen) < MAX_EXCERPTS and size + cost <= MAX_EVIDENCE_CHARS:
            chosen.append(excerpt)
            size += cost
    return chosen


def visible(text: str) -> str:
    """Escape invisible and control characters, so they can neither hide text from the model nor break the layout."""
    return "".join(ch if ch.isprintable() else _escape(ch) for ch in text)


def _read_lines(path: Path) -> list[str]:
    # Number lines the way the file's reader does, so that line N here is line N in the finding.
    if path.suffix == ".pth":
        return read_text(path).splitlines()  # Python's site module splits .pth files with splitlines()
    return read_source(path).split("\n")


def _window(path: str, text: list[str], group: list[int],
            marks: dict[int, tuple[int, set[str]]]) -> tuple[int, Excerpt]:
    start = max(1, group[0] - CONTEXT_LINES)
    end = min(len(text), group[-1] + CONTEXT_LINES)
    shortened = [_shorten(line.expandtabs(4)) for line in text[start - 1:end]]
    rules = sorted(set().union(*(marks[line][1] for line in group)))
    order = min(marks[line][0] for line in group)
    return order, Excerpt("", path, start, tuple(s for s, _ in shortened), tuple(c for _, c in shortened),
                          tuple(group), tuple(rules))


def _shorten(line: str) -> tuple[str, int]:
    shown: list[str] = []
    used = 0
    for count, ch in enumerate(line):
        piece = ch if ch.isprintable() else _escape(ch)
        if used + len(piece) > MAX_LINE_CHARS:
            return "".join(shown), len(line) - count
        shown.append(piece)
        used += len(piece)
    return "".join(shown), 0


def _escape(ch: str) -> str:
    return f"\\u{ord(ch):04x}" if ord(ch) <= 0xFFFF else f"\\U{ord(ch):08x}"
