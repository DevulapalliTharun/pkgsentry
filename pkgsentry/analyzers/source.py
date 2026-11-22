"""Read and parse untrusted Python source. Parsing builds a tree of the code; it never imports or runs it."""

import ast
import warnings
from pathlib import Path

MAX_PARSE_BYTES = 5 * 1024 * 1024
_DYNAMIC_IMPORTS = {"__import__", "importlib.import_module"}


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def parse_source(path: Path) -> ast.Module | None:
    if path.stat().st_size > MAX_PARSE_BYTES:
        return None
    return parse_text(path.read_bytes())


def parse_text(source: str | bytes) -> ast.Module | None:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # e.g. SyntaxWarning for "\(" in someone else's code
            return ast.parse(source)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None


def dotted(node: ast.AST | None) -> str:
    """os.path.join -> "os.path.join". Also sees through __import__("os").system and getattr(os, "system")."""
    attributes: list[str] = []
    while isinstance(node, ast.Attribute):  # a loop, not recursion: crafted attribute chains can be very long
        attributes.append(node.attr)
        node = node.value
    base = node.id if isinstance(node, ast.Name) else _dynamic_name(node)
    return ".".join([base, *reversed(attributes)]) if base else ""


def _dynamic_name(node: ast.AST | None) -> str:
    if isinstance(node, ast.Call) and node.args and isinstance(node.args[-1], ast.Constant):
        name, value = dotted(node.func), node.args[-1].value
        if name in _DYNAMIC_IMPORTS and len(node.args) == 1 and isinstance(value, str):
            return value
        if name == "getattr" and len(node.args) == 2 and isinstance(value, str):
            base = dotted(node.args[0])
            return f"{base}.{value}" if base else ""
    return ""


def import_aliases(tree: ast.Module) -> dict[str, str]:
    """Local name -> what it was imported as, e.g. _install -> setuptools.command.install.install."""
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                aliases[alias.asname or top] = alias.name if alias.asname else top
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return aliases


def full_name(node: ast.AST, aliases: dict[str, str]) -> str:
    head, _, rest = dotted(node).partition(".")
    full = aliases.get(head, head)
    return f"{full}.{rest}" if rest else full
