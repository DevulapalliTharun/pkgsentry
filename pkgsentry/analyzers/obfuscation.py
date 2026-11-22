"""Find source-level hiding tricks and compiled-only Python modules. The scanner never executes or imports samples."""

import ast
import base64
import math
import re
import io
import tokenize
import unicodedata
import warnings
import zlib
from collections import Counter
from pathlib import Path, PurePosixPath

from pkgsentry.analyzers.hooks import Hook
from pkgsentry.analyzers.rules import CONTEXTS, Finding, development_files
from pkgsentry.analyzers.source import dotted, parse_source, parse_text, read_text

_ORDER = {context: i for i, context in enumerate(CONTEXTS)}
_B64 = re.compile(r"[A-Za-z0-9+/]+={0,2}\Z")
_HEX = re.compile(r"[0-9a-fA-F]+\Z")
_SUSPICIOUS_CODE = re.compile(
    r"\b(exec|eval|compile|__import__)\s*\(|\b(subprocess|socket|requests|urllib|httpx)\b|"
    r"\.aws[/\\]credentials|\.ssh[/\\]id_\w+|GITHUB_TOKEN|AWS_SECRET_ACCESS_KEY",
    re.IGNORECASE,
)
_EXEC = {"exec", "eval", "compile", "builtins.exec", "builtins.eval", "builtins.compile"}
_STRING_BUILDERS = {"chr", "builtins.chr", "str.join", "bytes.fromhex", "codecs.decode"}
_MAX_LITERAL_BYTES = 256 * 1024
_MAX_UNPACKED_BYTES = 512 * 1024
_FORMAT_CONTROLS = {
    "\u00ad", "\u034f", "\u061c", "\u115f", "\u1160", "\u17b4", "\u17b5", "\u180e", "\u200b",
    "\u200c", "\u200d", "\u200e", "\u200f", "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
    "\u2060", "\u2066", "\u2067", "\u2068", "\u2069", "\ufeff",
}
_BIDI_CONTROLS = {"\u061c", "\u200e", "\u200f", "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
                   "\u2066", "\u2067", "\u2068", "\u2069"}


def scan_obfuscation(root: Path, kind: str, hooks: list[Hook], code_findings: list[Finding]) -> list[Finding]:
    """Find encoded source, runtime-built code, invisible format controls, and source-less .pyc modules."""
    contexts = {rel: "dev" for rel in development_files(root, kind)}
    contexts.update(_file_contexts(code_findings))
    install_paths = {
        hook.path for hook in hooks
        if hook.kind in {"setup.py", "in-tree build backend", "custom build hook", "module run by setup.py"}
    } | {hook.path for hook in hooks if hook.kind == "unreadable setup.py"}
    findings: list[Finding] = []
    sources = {path.relative_to(root).as_posix(): path for path in root.rglob("*.py") if path.is_file()}
    for rel, path in sorted(sources.items()):
        context = "install" if rel in install_paths else contexts.get(rel, "call")
        findings.extend(_source_findings(path, rel, context))
    findings.extend(_compiled_only(root, sources, contexts))
    unique = {(f.rule, f.path, f.line, f.detail): f for f in findings}
    return sorted(unique.values(), key=lambda f: (_ORDER[f.context], f.path, f.line, f.rule))


def _file_contexts(findings: list[Finding]) -> dict[str, str]:
    contexts: dict[str, str] = {}
    for finding in findings:
        previous = contexts.get(finding.path)
        if previous is None or _ORDER[finding.context] < _ORDER[previous]:
            contexts[finding.path] = finding.context
    return contexts


def _source_findings(path: Path, rel: str, context: str) -> list[Finding]:
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return []
    tree = parse_source(path)
    findings: list[Finding] = []
    if tree is not None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                decoded = _decode_source(node.value)
                suspicious = decoded is not None and bool(_SUSPICIOUS_CODE.search(decoded))
                if suspicious:
                    findings.append(_finding("encoded code", rel, node.lineno, context, _strength(context, "medium"),
                                             "encoded text decodes to code-like content", source))
                elif _is_encoded_literal(node.value):
                    findings.append(_finding("encoded string", rel, node.lineno, context, _strength(context, "weak"),
                                             "long high-entropy encoded string literal", source))
            if not isinstance(node, ast.Call) or dotted(node.func) not in _EXEC:
                continue
            if not node.args:
                continue
            argument = node.args[0]
            builders = {dotted(child.func) for child in ast.walk(argument) if isinstance(child, ast.Call)}
            if builders & _STRING_BUILDERS:
                strength = _strength(context, "strong" if context in {"install", "startup", "import"} else "medium")
                findings.append(_finding("string-built exec", rel, node.lineno, context, strength,
                                         "builds code from characters or encoded pieces, then executes it", source))
            if _has_high_entropy_constant(argument):
                strength = _strength(context, "strong" if context in {"install", "startup", "import"} else "medium")
                findings.append(_finding("encoded exec", rel, node.lineno, context, strength,
                                         "passes a long high-entropy value directly to code execution", source))
        findings.extend(_unicode_findings(source, rel, context))
    else:
        findings.extend(_unicode_findings(source, rel, context))
    return findings


def _decode_source(value: str) -> str | None:
    """Decode only bounded base64/hex text; never execute the result."""
    raw: bytes | None = None
    encoded = value.strip()
    if len(encoded) < 80 or len(encoded) > _MAX_LITERAL_BYTES:
        return None
    try:
        if _B64.fullmatch(encoded) and len(encoded) % 4 == 0:
            raw = base64.b64decode(encoded, validate=True)
        elif len(encoded) >= 160 and len(encoded) % 2 == 0 and _HEX.fullmatch(encoded):
            raw = bytes.fromhex(encoded)
    except (ValueError, base64.binascii.Error):
        return None
    if raw is None:
        return None
    if raw.startswith((b"\x78\x9c", b"\x78\xda", b"\x1f\x8b")):
        raw = _bounded_decompress(raw)
        if raw is None:
            return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in text) / max(1, len(text))
    if printable < 0.9:
        return None
    if parse_text(text) is None:
        return None
    return text


def _bounded_decompress(data: bytes) -> bytes | None:
    try:
        obj = zlib.decompressobj(31 if data.startswith(b"\x1f\x8b") else zlib.MAX_WBITS)
        result = obj.decompress(data, _MAX_UNPACKED_BYTES + 1)
        if len(result) > _MAX_UNPACKED_BYTES or obj.unconsumed_tail:
            return None
        result += obj.flush(_MAX_UNPACKED_BYTES + 1 - len(result))
        return result if obj.eof and len(result) <= _MAX_UNPACKED_BYTES else None
    except (zlib.error, ValueError):
        return None


def _is_encoded_literal(value: str) -> bool:
    stripped = value.strip()
    return (len(stripped) >= 160 and len(stripped) <= _MAX_LITERAL_BYTES
            and (_B64.fullmatch(stripped) is not None or len(stripped) % 2 == 0 and _HEX.fullmatch(stripped) is not None)
            and _entropy(stripped) >= 3.5)


def _has_high_entropy_constant(node: ast.AST) -> bool:
    return any(isinstance(child, ast.Constant) and isinstance(child.value, str) and _is_encoded_literal(child.value)
               for child in ast.walk(node))


def _entropy(value: str) -> float:
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _unicode_findings(source: str, rel: str, context: str) -> list[Finding]:
    try:
        lines = source.splitlines()
    except MemoryError:
        return []
    controls_by_line: dict[int, set[str]] = {}
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            for token in tokenize.generate_tokens(io.StringIO(source).readline):
                if token.type in {tokenize.STRING, tokenize.COMMENT}:
                    allowed = _BIDI_CONTROLS
                else:
                    allowed = _FORMAT_CONTROLS
                for offset, text in enumerate(token.string.splitlines()):
                    controls = {ch for ch in text if ch in allowed or
                                (token.type not in {tokenize.STRING, tokenize.COMMENT}
                                 and unicodedata.category(ch) == "Cf")}
                    if controls:
                        controls_by_line.setdefault(token.start[0] + offset, set()).update(controls)
    except (tokenize.TokenError, IndentationError, MemoryError):
        for number, line in enumerate(lines, 1):
            controls = {ch for ch in line if ch in _BIDI_CONTROLS}
            if controls:
                controls_by_line[number] = controls
    findings = []
    for number, found in sorted(controls_by_line.items()):
        controls = sorted(found)
        if not controls:
            continue
        names = ", ".join(f"U+{ord(ch):04X} {unicodedata.name(ch, 'UNKNOWN')}" for ch in controls)
        strength = _strength(context, "medium" if context in {"install", "startup", "import"} else "weak")
        findings.append(_finding("invisible unicode", rel, number, context, strength,
                                 f"contains invisible formatting characters: {names}", "\n".join(lines)))
    return findings


def _compiled_only(root: Path, sources: dict[str, Path], contexts: dict[str, str]) -> list[Finding]:
    source_stems = {PurePosixPath(rel).with_suffix("").as_posix() for rel in sources}
    findings = []
    for path in root.rglob("*.pyc"):
        rel = path.relative_to(root).as_posix()
        stem_path = path.with_suffix("")
        if stem_path.parent.name == "__pycache__":
            module = stem_path.name.split(".", 1)[0]
            source_rel = (stem_path.parent.parent / f"{module}.py").relative_to(root).as_posix()
        else:
            source_rel = f"{stem_path}.py"
        if PurePosixPath(source_rel).with_suffix("").as_posix() in source_stems:
            continue
        context = contexts.get(source_rel, "call")
        findings.append(Finding("compiled-only module", rel, 0, context, _strength(context, "weak"),
                                "Python bytecode is present without corresponding readable .py source", ""))
    return findings


def _strength(context: str, level: str) -> str:
    if context == "dev":
        return "info"
    if level == "strong":
        return "strong" if context in {"install", "startup", "import"} else "medium"
    if level == "medium":
        return "medium" if context in {"install", "startup", "import"} else "weak"
    return "weak"


def _finding(rule: str, path: str, line: int, context: str, strength: str, detail: str, source: str) -> Finding:
    lines = source.splitlines()
    evidence = lines[line - 1].strip()[:160] if 0 < line <= len(lines) else ""
    return Finding(rule, path, line, context, strength, detail, evidence)
