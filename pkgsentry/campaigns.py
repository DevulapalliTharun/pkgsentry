"""Campaigns: packages that share attacker infrastructure.

An indicator links packages only when it belongs to one attacker: their own domain or IP address, or their own
webhook, bot, paste or file on a shared service. The shared service itself (github.com, discord.com) never links."""

import ast
import base64
import binascii
import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from pkgsentry.analyzers.rules import Finding
from pkgsentry.analyzers.source import parse_source, read_source, read_text

MAX_STRING = 10_000
_URL = re.compile(r"\b(?:https?|ftp|wss?)://[^\s'\"<>`\\]+", re.IGNORECASE)
_IP_WITH_PORT = re.compile(r"((?:\d{1,3}\.){3}\d{1,3})(?::\d{1,5})?")
_BASE64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
# Shared services: only the account in the path links packages. Hosts are matched whole, so an account that lives
# in the hostname (bucket.s3.amazonaws.com, <token>.webhook.site) links by that hostname instead.
_ACCOUNTS = [(label, re.compile(host), re.compile(path)) for label, host, path in [
    ("Discord webhook", r"(?:ptb\.|canary\.)?discord(?:app)?\.com", r"/api/webhooks/(\d+)"),
    ("Discord channel", r"cdn\.discordapp\.com|media\.discordapp\.net", r"/attachments/(\d+)/"),
    ("Telegram bot", r"api\.telegram\.org", r"/bot(\d+):"),
    ("Bale bot", r"tapi\.bale\.ai", r"/bot(\d+):"),
    ("Telegraph page", r"(?:api\.)?telegra\.ph", r"/(?:getPage/)?([\w-]+)"),
    ("Slack webhook", r"hooks\.slack\.com", r"/services/(\w+/\w+)"),
    ("webhook.site token", r"webhook\.site", r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"),
    ("Pastebin paste", r"(?:www\.)?pastebin\.com", r"/(?:raw/)?([A-Za-z0-9]{8})(?![A-Za-z0-9])"),
    ("ntfy topic", r"ntfy\.sh", r"/([\w-]+)"),
    ("GitHub user", r"(?:raw|gist)\.githubusercontent\.com|gist\.github\.com", r"/([\w.-]+)/"),
    ("GitHub user", r"(?:www\.)?github\.com", r"/([\w.-]+)/[\w.-]+/(?:releases/download|raw)/"),
    ("GitHub user", r"api\.github\.com", r"/repos/([\w.-]+)/"),
    ("GitHub user", r"cdn\.jsdelivr\.net", r"/gh/([\w.-]+)/"),
    ("cloud bucket", r"storage\.googleapis\.com|s3(?:[.-][\w-]+)?\.amazonaws\.com", r"/([\w.-]+)/"),
    ("IPFS content", r"gateway\.pinata\.cloud|ipfs\.io|dweb\.link", r"/ipfs/(\w+)"),
    ("shared file", r"(?:[\w-]+\.)?gofile\.io", r"/(?:d|download/web)/([\w-]+)"),
    ("shared file", r"tmpfiles\.org", r"/dl/(\w+)/"),
    ("shared file", r"transfer\.sh|transfer\.archivete\.am", r"/(\w+)/"),
]]
# Never attacker-specific: code hosting, package indexes, references and public utilities that honest and malicious
# packages alike contact. A listed name also covers its subdomains.
_SHARED_HOSTS = (
    "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org", "sourceforge.net", "pypi.org",
    "pythonhosted.org", "python.org", "readthedocs.io", "readthedocs.org", "wikipedia.org", "gnu.org",
    "example.com", "example.org", "example.net",
    "google.com", "googleapis.com", "microsoft.com", "apple.com", "amazon.com", "discord.com", "discordapp.com",
    "telegram.org", "ipify.org", "ipinfo.io", "ip-api.com", "ifconfig.me", "icanhazip.com", "ident.me",
    "checkip.amazonaws.com", "httpbin.org", "canarytokens.com",
)
_PUBLIC_RESOLVERS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "208.67.222.222"}
# Addresses that can only mean this machine, its own network or cloud metadata, never an attacker's server.
_LOCAL_NETWORKS = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
    "224.0.0.0/4", "240.0.0.0/4", "::/127", "fc00::/7", "fe80::/10", "ff00::/8")]
_LOCAL_SUFFIXES = (".localhost", ".local", ".internal", ".lan", ".home.arpa")


@dataclass(frozen=True)
class Indicator:
    kind: str  # "url" or "ip"
    value: str
    key: str  # what links packages; "" for a shared service, which never links
    path: str
    line: int
    hidden: bool  # found only after decoding base64


@dataclass(frozen=True)
class Campaign:
    packages: tuple[str, ...]
    links: tuple[tuple[str, tuple[str, ...]], ...]  # (key, the packages that share it)


def url_key(url: str) -> str | None:
    """The link key of a URL: "" when it cannot link packages, None when it is not an outside indicator at all."""
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").rstrip(".")
    except ValueError:
        return None
    if _IP_WITH_PORT.fullmatch(host) or ":" in host:
        return ip_key(host)
    if "." not in host or host.endswith(_LOCAL_SUFFIXES):
        return None
    for label, host_pattern, path_pattern in _ACCOUNTS:
        if host_pattern.fullmatch(host):
            account = path_pattern.match(parts.path)
            return f"{label} {account.group(1)}" if account else ""
    return "" if any(host == h or host.endswith(f".{h}") for h in _SHARED_HOSTS) else f"host {host}"


def ip_key(text: str) -> str | None:
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return None
    if any(ip in network for network in _LOCAL_NETWORKS):
        return None
    return "" if str(ip) in _PUBLIC_RESOLVERS else f"IP {ip}"


def indicators_in_text(text: str) -> list[tuple[str, str, str]]:
    """(kind, value, link key) for each URL in a string, or for the string itself when it is an IP address."""
    text = text[:MAX_STRING]
    found = []
    for match in _URL.finditer(text):
        url = match.group(0).rstrip(".,;:)]}")
        key = url_key(url)
        if key is not None:
            found.append(("url", url, key))
    whole = _IP_WITH_PORT.fullmatch(text.strip())
    if whole and (key := ip_key(whole.group(1))) is not None:
        found.append(("ip", whole.group(1), key))
    return found


def extract_indicators(root: Path, findings: list[Finding]) -> list[Indicator]:
    """URLs and IP addresses in the string literals of files with a non-info finding, also inside base64."""
    found: dict[tuple[str, str], Indicator] = {}
    for rel in sorted({f.path for f in findings if f.strength != "info" and f.path.endswith((".py", ".pth"))}):
        path = root / rel
        strings = (list(enumerate(read_text(path).splitlines(), 1)) if rel.endswith(".pth")
                   else _string_constants(path))
        for line, text in strings:
            for hidden, candidate in ((False, text), (True, _decoded(text))):
                for kind, value, key in indicators_in_text(candidate) if candidate else []:
                    found.setdefault((value, rel), Indicator(kind, value, key, rel, line, hidden))
    return sorted(found.values(), key=lambda i: (i.key == "", i.path, i.line, i.value))


def link(keys_by_package: dict[str, set[str]]) -> list[Campaign]:
    """Group packages that share a key, directly or through a chain of shared keys (union-find)."""
    parent = {name: name for name in keys_by_package}

    def find(name: str) -> str:
        while parent[name] != name:
            parent[name] = parent[parent[name]]  # path halving keeps the chains short
            name = parent[name]
        return name

    owners: dict[str, list[str]] = {}
    for name, keys in keys_by_package.items():
        for key in keys - {""}:
            owners.setdefault(key, []).append(name)
    for names in owners.values():
        for other in names[1:]:
            parent[find(other)] = find(names[0])
    groups: dict[str, list[str]] = {}
    for name in keys_by_package:
        groups.setdefault(find(name), []).append(name)
    campaigns = []
    for members in (sorted(g) for g in groups.values() if len(g) > 1):
        links = tuple(sorted((key, tuple(sorted(names))) for key, names in owners.items()
                             if len(names) > 1 and names[0] in members))
        campaigns.append(Campaign(tuple(members), links))
    return sorted(campaigns, key=lambda c: (-len(c.packages), c.packages))


def _string_constants(path: Path) -> list[tuple[int, str]]:
    tree = parse_source(path)
    if tree is None:  # cannot be parsed (often Python 2): fall back to the raw lines
        return list(enumerate(read_source(path).split("\n"), 1))
    # A string on its own line is a docstring or a note: it does nothing, and docs are full of links.
    notes = {id(node.value) for node in ast.walk(tree) if isinstance(node, ast.Expr)}
    return [(node.lineno, node.value if isinstance(node.value, str) else node.value.decode("latin-1"))
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)) and id(node) not in notes]


def _decoded(text: str) -> str:
    """Bounded base64 decoding, so a URL hidden as base64 is still found. The result is only read, never run."""
    text = text.strip()
    if len(text) > MAX_STRING or len(text) % 4 or not _BASE64.fullmatch(text):
        return ""
    try:
        decoded = base64.b64decode(text, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return ""
    return decoded if all(ch.isprintable() or ch in "\r\n\t" for ch in decoded) else ""
