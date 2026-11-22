"""Does a package name imitate a popular package? Only names are compared; nothing is downloaded."""

import json
import re
import sys
from dataclasses import dataclass
from functools import cache
from importlib import resources

_SEPARATORS = re.compile(r"[-_.]+")
# PyPI's ultranormalize rule treats l/i/1 and o/0 as one character; it does not cover these letter pairs.
_LOOKALIKE_PAIRS = (("rn", "m"), ("vv", "w"))
_ULTRA = str.maketrans("lio", "110")
_PREFIXES = ("python3-", "python-", "py3-", "py-", "py")
_SUFFIXES = ("-python3", "-python", "-py3", "-py", "-lib", "3", "2")
_STRENGTH_ORDER = {"strong": 0, "medium": 1, "weak": 2}
# Modules removed from the standard library in Python 3.12 and 3.13 (PEP 594, PEP 632). sys.stdlib_module_names
# no longer lists them, but people still try to pip install them, so the names are attractive to squat.
_REMOVED_STDLIB = {
    "aifc", "asynchat", "asyncore", "audioop", "cgi", "cgitb", "chunk", "crypt", "distutils", "imghdr", "imp",
    "lib2to3", "mailcap", "msilib", "nis", "nntplib", "ossaudiodev", "pipes", "smtpd", "sndhdr", "spwd", "sunau",
    "telnetlib", "uu", "xdrlib",
}


@dataclass(frozen=True)
class Popular:
    name: str
    rank: int
    downloads: int


@dataclass(frozen=True)
class TyposquatMatch:
    target: Popular
    technique: str
    distance: int
    strength: str  # "strong", "medium" or "weak"


@dataclass(frozen=True)
class NameCheck:
    name: str
    normalized: str
    popular: Popular | None  # set when the name itself is a popular package
    stdlib_module: bool
    matches: tuple[TyposquatMatch, ...]


def normalize(name: str) -> str:
    """PyPI's canonical form (PEP 503): lower case, and any run of - _ . becomes a single -."""
    return _SEPARATORS.sub("-", name).lower()


@cache
def popular_packages() -> tuple[Popular, ...]:
    data = json.loads(resources.files("pkgsentry.data").joinpath("top_packages.json").read_text())
    return tuple(Popular(normalize(name), rank, count) for rank, (name, count) in enumerate(data["rows"], 1))


def check_name(name: str, popular: tuple[Popular, ...] | None = None) -> NameCheck:
    popular = popular_packages() if popular is None else popular
    normalized = normalize(name)
    module_name = normalized.replace("-", "_")
    is_stdlib = module_name in sys.stdlib_module_names or module_name in _REMOVED_STDLIB
    for target in popular:
        if target.name == normalized:
            return NameCheck(name, normalized, target, is_stdlib, ())
    shape = _shape(name)
    matches = [match for target in popular if (match := _compare(normalized, shape, target))]
    matches.sort(key=lambda m: (_STRENGTH_ORDER[m.strength], m.target.rank))
    return NameCheck(name, normalized, None, is_stdlib, tuple(matches[:5]))


def edit_distance(a: str, b: str) -> int:
    """Insertions, deletions, substitutions and swaps of two neighbouring letters each cost 1."""
    before_previous: list[int] = []
    previous = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        current = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            current[j] = min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                current[j] = min(current[j], before_previous[j - 2] + 1)
        before_previous, previous = previous, current
    return previous[-1]


def _compare(candidate: str, shape: str, target: Popular) -> TyposquatMatch | None:
    known = target.name
    if candidate.replace("-", "") == known.replace("-", ""):
        return TyposquatMatch(target, "separator trick", 0, "strong")
    if shape == _shape(known):
        return TyposquatMatch(target, "look-alike characters", 0, "strong")
    if "-" in known and sorted(candidate.split("-")) == sorted(known.split("-")):
        return TyposquatMatch(target, "swapped words", 0, "strong" if target.rank <= 1000 else "medium")
    limit = _allowed_distance(len(known))
    if limit and abs(len(candidate) - len(known)) <= limit:
        distance = edit_distance(candidate, known)
        if distance <= limit:
            strength = "strong" if distance == 1 and target.rank <= 1000 else "medium"
            technique = _describe_edit(candidate, known, distance)
            return TyposquatMatch(target, technique, distance, strength)
    affix = _added_affix(candidate, known)
    if affix:
        strength = "medium" if target.rank <= 100 else "weak"
        return TyposquatMatch(target, f"added {affix}", len(candidate) - len(known), strength)
    return None


def _allowed_distance(length: int) -> int:
    if length < 5:
        return 0  # short names sit one edit away from many honest packages
    return 1 if length < 9 else 2


def _shape(name: str) -> str:
    """PyPI's ultranormalize_name (drop - _ . and map l/i -> 1, o -> 0), plus rn -> m and vv -> w."""
    name = _SEPARATORS.sub("", name.lower())
    for lookalike, letter in _LOOKALIKE_PAIRS:
        name = name.replace(lookalike, letter)
    return name.translate(_ULTRA)


def _describe_edit(candidate: str, known: str, distance: int) -> str:
    if distance > 1:
        return f"{distance} edits"
    if len(candidate) > len(known):
        return "extra letter"
    if len(candidate) < len(known):
        return "missing letter"
    differences = sum(1 for a, b in zip(candidate, known) if a != b)
    return "swapped letters" if differences == 2 else "changed letter"


def _added_affix(candidate: str, known: str) -> str:
    if len(known) < 4:
        return ""
    for prefix in _PREFIXES:
        if candidate == prefix + known:
            return f"prefix '{prefix}'"
    for suffix in _SUFFIXES:
        if candidate == known + suffix:
            return f"suffix '{suffix}'"
    return ""
