"""What does the code do? AST rules for hidden code execution, starting programs, network use, secrets and
persistence. Each finding is weighted by when its code runs (Step 4). Nothing is imported or run."""

import ast
import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from pkgsentry.analyzers.hooks import Hook, single_top_folder
from pkgsentry.analyzers.source import dotted, full_name, import_aliases, parse_source, parse_text, read_text

# install: setup.py and code it loads; startup: .pth lines; import: module top level and functions it calls;
# call: runs only when someone calls it; dev: tests, docs, examples and scripts that are not installed.
CONTEXTS = ("install", "startup", "import", "call", "dev")
# Strength of each behaviour by context (columns follow CONTEXTS), set from measurements on honest packages.
_STRENGTH = {
    "decoded exec": ("strong", "strong", "strong", "strong", "medium"),
    "exec": ("weak", "medium", "weak", "info", "info"),
    "process": ("weak", "strong", "medium", "info", "info"),
    "risky command": ("strong", "strong", "strong", "weak", "info"),
    "network": ("medium", "strong", "medium", "info", "info"),
    "endpoint": ("strong", "strong", "strong", "weak", "info"),
    "short link": ("medium", "medium", "weak", "info", "info"),
    "secret": ("medium", "strong", "weak", "weak", "info"),
    "environment": ("medium", "strong", "medium", "weak", "info"),
    "persistence": ("medium", "strong", "weak", "weak", "info"),
    "secret + network": ("strong", "strong", "strong", "weak", "info"),
    "endpoint + network": ("strong", "strong", "strong", "weak", "info"),
}
_WEAKER = {"strong": "medium", "medium": "weak", "weak": "info", "info": "info"}
_ORDER = {"strong": 0, "medium": 1, "weak": 2, "info": 3}

_EXEC_CALLS = {"exec", "eval", "compile", "execfile", "builtins.exec", "builtins.eval", "builtins.compile",
               "runpy.run_path", "runpy.run_module"}
_PROCESS_CALLS = {
    "os.system", "os.popen", "os.startfile", "os.posix_spawn", "os.posix_spawnp", "pty.spawn",
    *(f"os.exec{s}" for s in ("l", "le", "lp", "lpe", "v", "ve", "vp", "vpe")),
    *(f"os.spawn{s}" for s in ("l", "le", "lp", "lpe", "v", "ve", "vp", "vpe")),
    *(f"subprocess.{f}" for f in ("Popen", "run", "call", "check_call", "check_output", "getoutput",
                                  "getstatusoutput")),
    "commands.getoutput", "commands.getstatusoutput", "asyncio.create_subprocess_exec",
    "asyncio.create_subprocess_shell",
}
# Calls that send or receive data right away.
_NETWORK_SENDS = {
    "socket.create_connection", "socket.gethostbyname", "urllib.request.urlopen", "urllib.request.urlretrieve",
    "urllib2.urlopen", "urllib.urlopen", "urllib.urlretrieve", "aiohttp.request", "urllib3.request",
    *(f"requests.{f}" for f in ("get", "post", "put", "patch", "delete", "head", "request")),
    *(f"httpx.{f}" for f in ("get", "post", "put", "patch", "delete", "head", "request", "stream")),
    "websocket.create_connection", "websockets.connect",
}
# Client objects: creating one sends nothing; traffic starts when one of _TRAFFIC_METHODS is called on it.
_NETWORK_CLIENTS = {
    "socket.socket", "requests.Session", "requests.session", "httpx.Client", "httpx.AsyncClient",
    "aiohttp.ClientSession", "urllib3.PoolManager", "urllib3.HTTPConnectionPool", "urllib3.HTTPSConnectionPool",
    "http.client.HTTPConnection", "http.client.HTTPSConnection", "httplib.HTTPConnection", "httplib.HTTPSConnection",
    "urllib.request.build_opener", "urllib2.build_opener", "ftplib.FTP", "ftplib.FTP_TLS", "smtplib.SMTP",
    "smtplib.SMTP_SSL", "telnetlib.Telnet",
}
_CONNECT_ON_CREATE = {"ftplib.FTP", "ftplib.FTP_TLS", "smtplib.SMTP", "smtplib.SMTP_SSL", "telnetlib.Telnet"}  # if given a host
_TRAFFIC_METHODS = {"connect", "connect_ex", "send", "sendall", "sendto", "sendmail", "send_message", "request",
                    "get", "post", "put", "patch", "delete", "head", "open", "urlopen", "stream", "storbinary",
                    "retrbinary", "login", "getresponse", "endheaders"}
# Calls that run a function handed to them (now, in a thread, or when the program exits).
_SCHEDULERS = {"threading.Thread", "threading.Timer", "multiprocessing.Process", "atexit.register", "map"}
_DECODERS = ("base64.", "binascii.", "codecs.decode", "zlib.decompress", "gzip.decompress", "bz2.decompress",
             "lzma.decompress", "marshal.loads", "bytes.fromhex", "pickle.loads")
_FILE_READERS = {"open", "io.open", "codecs.open"}
_READ_METHODS = (".read", ".read_text", ".read_bytes")
_ENV_SERIALIZERS = {"json.dumps", "pickle.dumps", "yaml.dump", "yaml.safe_dump", "base64.b64encode"}
_ENV_WHOLE = {"os.environ.copy", "os.environ.items", "os.environ.values"}
_ENV_READERS = {"os.getenv", "os.environ.get", "os.environ.pop"}
_CREDENTIAL_ENV = re.compile(r"aws_secret_access_key|aws_session_token|github_token|gh_token|npm_token|"
                             r"twine_password|discord_token", re.IGNORECASE)

_URL = re.compile(r"\b(?:https?|ftp)://([a-z0-9.-]+|\[[0-9a-f:.]+\])(?::\d+)?(/[^\s'\"<>]*)?")
_CONNECT_METHODS = ("connect", "connect_ex", "create_connection", "sendto")
_MAX_NESTING = 3  # exec("exec('...')") is checked this many levels deep
_SHADY_HOSTS = {
    **dict.fromkeys(["pastebin.com", "paste.ee", "hastebin.com", "rentry.co", "rentry.org"], "paste site"),
    **dict.fromkeys(["transfer.sh", "file.io", "gofile.io", "anonfiles.com"], "file-sharing site"),
    **dict.fromkeys(["ngrok.io", "ngrok-free.app", "ngrok.app", "trycloudflare.com", "serveo.net", "loca.lt"],
                    "tunnel to a private machine"),
    **dict.fromkeys(["webhook.site", "requestbin.net", "pipedream.net", "oastify.com", "oast.pro", "oast.live",
                     "oast.site", "oast.online", "oast.fun", "oast.me", "burpcollaborator.net", "interact.sh"],
                    "request-capture service"),
    **dict.fromkeys(["bit.ly", "tinyurl.com", "cutt.ly", "is.gd", "rb.gy"], "URL shortener"),
}
_SHADY_PATHS = {("discord.com", "/api/webhooks"): "Discord webhook", ("discordapp.com", "/api/webhooks"):
                "Discord webhook", ("api.telegram.org", "/bot"): "Telegram bot API"}
_SEP = r"[/\\]"
_STRING_RULES = [(re.compile(pattern, re.IGNORECASE), rule, what) for pattern, rule, what in [
    (rf"(^|{_SEP}|~)\.ssh({_SEP}(id_\w+|identity)?)?$|\bid_(rsa|dsa|ecdsa|ed25519)\b", "secret", "SSH keys"),
    (rf"\.aws{_SEP}credentials", "secret", "AWS credentials file"),
    (rf"(^|{_SEP}|~)\.kube{_SEP}config|\.docker{_SEP}config\.json", "secret", "Kubernetes or Docker credentials"),
    (rf"(^|{_SEP}|~)([._]netrc|\.pypirc|\.npmrc|\.git-credentials)$", "secret", "saved passwords for developer tools"),
    (rf"(^|{_SEP}|~)\.gnupg({_SEP}|$)", "secret", "GPG keys"),
    (r"^/etc/(passwd|shadow|sudoers)$", "secret", "system account files"),
    (rf"(^|{_SEP})(login data|local state|web data)$|cookies\.sqlite$|logins\.json$|key4\.db$",
     "secret", "browser passwords or cookies"),
    (rf"local storage{_SEP}+leveldb", "secret", "browser or Discord token storage"),
    (rf"wallet\.dat$|(^|{_SEP})(exodus|electrum)({_SEP}|$)", "secret", "cryptocurrency wallet"),
    (rf"(^|{_SEP}|~)\.(bash|zsh)_history$", "secret", "shell history"),
    (r"application_default_credentials\.json", "secret", "Google Cloud credentials"),
    (r"\b(curl|wget)\b[^|;\n]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b", "risky command", "a download piped into a shell"),
    (r"/dev/tcp/|\bnc(at)?\s+(-\w+\s+)*-e\s", "risky command", "a reverse-shell command"),
    (r"powershell[^\n]*\s-(e|en|enc|encodedcommand)\s|\binvoke-expression\b|\biex\s*\(|downloadstring\(",
     "risky command", "a hidden or downloading PowerShell command"),
    (r"\bcertutil\b[^\n]*-urlcache|\bbitsadmin\b[^\n]*/transfer|\bmshta\s+https?:", "risky command",
     "a Windows tool used to download files"),
    (rf"(^|{_SEP}|~)\.(bashrc|zshrc|bash_profile|zprofile|profile)$", "persistence", "shell startup file"),
    (rf"(^|{_SEP})(crontab|cron\.d)({_SEP}|$)|^crontab\b|\bschtasks\b", "persistence", "scheduled task"),
    (rf"library{_SEP}launch(agents|daemons)", "persistence", "macOS launch agent"),
    (rf"start menu{_SEP}+programs{_SEP}+startup|currentversion{_SEP}+run(once)?\b", "persistence",
     "Windows autostart location"),
    (rf"{_SEP}systemd{_SEP}+(system|user)\b", "persistence", "systemd service"),
    (rf"(^|{_SEP})authorized_keys$", "persistence", "SSH authorized_keys"),
]]
_TEXT_RULES = [
    ("exec", re.compile(r"\b(exec|eval|execfile)\b")),
    ("process", re.compile(r"\bos\.(system|popen|spawn\w*|exec\w+)\s*\(|\bsubprocess\.\w+\s*\(|\bcommands\.get")),
    ("network", re.compile(r"\bsocket\.(socket|create_connection)\b|\burlopen\s*\(|\burllib2\b|\bhttplib\b|"
                           r"\brequests\.(get|post)\s*\(")),
]
_QUOTED = re.compile(r"(['\"])(.+?)\1")
_DEV_FOLDERS = {"test", "tests", "testing", "doc", "docs", "example", "examples", "benchmark", "benchmarks"}
_NESTED_DEV_FOLDERS = _DEV_FOLDERS | {"demo", "demos", "sample", "samples"}  # only below a package, never its name
# Top-level names that setuptools' automatic discovery never installs (setuptools/discovery.py, flat layout).
_NOT_INSTALLED_FOLDERS = {
    "ci", "bin", "debian", "doc", "docs", "documentation", "manpages", "news", "newsfragments", "changelog",
    "test", "tests", "unit_test", "unit_tests", "example", "examples", "scripts", "tools", "util", "utils",
    "python", "build", "dist", "venv", "env", "requirements", "tasks", "fabfile", "site_scons", "benchmark",
    "benchmarks", "exercise", "exercises", "htmlcov",
}
_NOT_INSTALLED_MODULES = {
    "conftest", "test", "tests", "example", "examples", "build", "toxfile", "noxfile", "pavement", "dodo", "tasks",
    "fabfile", "sconstruct", "conanfile", "manage", "benchmark", "benchmarks", "exercise", "exercises",
}
_ENTRY_POINT = re.compile(r"=\s*[\"']?([A-Za-z_]\w*)[.:]")  # console_scripts: "cmd = pkg.mod:func"
_IMPORT_FUNCTIONS = {"__import__", "import_module", "run_module"}
_CONFIG_FILES = {"setup.py", "setup.cfg", "pyproject.toml", "entry_points.txt"}
_MAX_STRING = 10_000


@dataclass(frozen=True)
class Finding:
    rule: str
    path: str
    line: int
    context: str  # one of CONTEXTS
    strength: str
    detail: str
    evidence: str  # the source line


def check_code(root: Path, kind: str, hooks: list[Hook]) -> list[Finding]:
    """kind is "sdist" or "wheel" (from PyPI); hooks come from Step 4 and say which files run at install."""
    paths = {p.relative_to(root).as_posix(): p for p in sorted(root.rglob("*.py")) if p.is_file()}
    top = "" if kind == "wheel" else single_top_folder(paths)
    trees = {rel: parse_source(path) for rel, path in paths.items()}
    dev = _dev_files(root, paths, trees, top, kind)
    whole_file = {h.path for h in hooks if h.kind in ("setup.py", "unreadable setup.py", "in-tree build backend",
                                                      "custom build hook")}
    loaded_by_setup = {h.path for h in hooks if h.kind == "module run by setup.py"} | _named_by(trees, whole_file)
    findings: list[Finding] = []
    for rel, path in paths.items():
        if rel in whole_file:
            findings += _check_file(path, rel, "install", trees[rel])
        elif rel in loaded_by_setup:
            findings += _check_file(path, rel, "", trees[rel], top_level="install")
        else:
            findings += _check_file(path, rel, "dev" if rel in dev else "", trees[rel])
    for rel in sorted({h.path for h in hooks if h.kind == ".pth startup code"}):
        findings += _check_pth(root / rel, rel)
    unique = {(f.rule, f.path, f.line, f.detail): f for f in findings}
    return sorted(unique.values(), key=lambda f: (_ORDER[f.strength], f.path, f.line, f.rule))


def development_files(root: Path, kind: str) -> set[str]:
    """Return source files Step 5 classifies as tests/docs/helpers rather than installed package code."""
    paths = {p.relative_to(root).as_posix(): p for p in sorted(root.rglob("*.py")) if p.is_file()}
    top = "" if kind == "wheel" else single_top_folder(paths)
    trees = {rel: parse_source(path) for rel, path in paths.items()}
    return _dev_files(root, paths, trees, top, kind)


def _dev_files(root: Path, paths: dict[str, Path], trees: dict[str, ast.Module | None], top: str,
               kind: str) -> set[str]:
    """Files that are never installed or run for a user: tests, docs, examples and helper scripts. Location alone is
    never enough: anything that installed code imports (directly or through other imports), or that configuration
    names as an entry point, stays installed code, so an attacker cannot hide a payload by naming a folder "tests"."""
    inner = {rel: rel.removeprefix(top) for rel in paths}
    modules = {rel: _module_parts(r) for rel, r in inner.items()}
    folders = {r.split("/")[0] for r in inner.values() if "/" in r}
    packages = {r.split("/")[0] for r in inner.values() if "/" in r and r.endswith("__init__.py")}
    roots: set[str] = set()  # dev candidates
    for rel, r in inner.items():
        parts = PurePosixPath(r).parts
        head, name = parts[0].removesuffix(".py"), parts[-1]
        nested = modules[rel][1:-1]
        if len(parts) > 1 and head.lower().lstrip("_") in _DEV_FOLDERS \
                or any(p.lower().lstrip("_") in _NESTED_DEV_FOLDERS for p in nested) \
                or name.startswith("test_") or name.endswith("_test.py") or name == "conftest.py":
            roots.add(rel)
        elif kind == "sdist" and parts[0] not in packages | {"src", "setup.py"}:
            reserved = _NOT_INSTALLED_FOLDERS if len(parts) > 1 else _NOT_INSTALLED_MODULES
            if head.lower() in reserved or head.startswith((".", "_")) or not head.isidentifier() \
                    or packages or "src" in folders:
                roots.add(rel)  # a reserved name, or a helper folder or script beside the real packages
    used = _imported_modules(trees, [rel for rel in paths if rel not in roots], modules) | _config_names(root, top)
    changed = True
    while changed:  # a dev file that installed code imports or runs is installed code, and so is what it imports
        changed = False
        for rel in list(roots):
            if ".".join(modules[rel]) in used or f"file:{PurePosixPath(rel).name}" in used:
                roots.remove(rel)
                used |= _imported_modules(trees, [rel], modules)
                changed = True
    return roots


def _module_parts(rel: str) -> list[str]:
    """src/demo/x.py -> ["demo", "x"]; demo/__init__.py -> ["demo"]."""
    parts = list(PurePosixPath(rel).with_suffix("").parts)
    if len(parts) > 1 and parts[0] == "src":
        parts.pop(0)
    if len(parts) > 1 and parts[-1] == "__init__":
        parts.pop()
    return parts


def _imported_modules(trees: dict[str, ast.Module | None], files: list[str],
                      modules: dict[str, list[str]]) -> set[str]:
    """Module names the given files import, relative imports resolved (import a.b gives a and a.b), including
    __import__("x") and import_module("x") with a fixed name, plus "file:x.py" for .py file names in strings."""
    found: set[str] = set()
    for rel in files:
        tree = trees.get(rel)
        for node in ast.walk(tree) if tree is not None else ():
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                base = node.module.split(".") if node.module else []
                if node.level:
                    package = modules[rel] if rel.endswith("__init__.py") else modules[rel][:-1]
                    if node.level - 1 > len(package):
                        continue
                    base = package[:len(package) - node.level + 1] + base
                names = [".".join(base), *(".".join([*base, alias.name]) for alias in node.names)]
            elif isinstance(node, ast.Call) and dotted(node.func).rpartition(".")[2] in _IMPORT_FUNCTIONS \
                    and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                names = [node.args[0].value]
            elif isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.endswith(".py"):
                found.add(f"file:{PurePosixPath(node.value).name}")
                continue
            else:
                continue
            for name in names:
                parts = name.split(".")
                found |= {".".join(parts[:i]) for i in range(1, len(parts) + 1)}
    return found


def _config_names(root: Path, top: str) -> set[str]:
    """Modules that configuration runs: entry points (cmd = pkg.mod:func) and .pth import lines."""
    names: set[str] = set()
    for path in root.rglob("*"):
        if not path.is_file() or path.stat().st_size > _MAX_STRING * 100:
            continue
        if path.suffix == ".pth":
            names |= {w for line in read_text(path).splitlines() if line.startswith(("import ", "import\t"))
                      for w in re.findall(r"[A-Za-z_][\w.]*", line[7:])}
        elif path.name in _CONFIG_FILES and (path.name == "entry_points.txt"
                                             or path.relative_to(root).as_posix() == f"{top}{path.name}"):
            names |= set(_ENTRY_POINT.findall(read_text(path)))
    return {".".join(n.split(".")[:i]) for n in names for i in range(1, n.count(".") + 2)}


def _named_by(trees: dict[str, ast.Module | None], sources: set[str]) -> set[str]:
    """.py files whose name appears as a string in install-time code: exec(open("x.py").read()) runs x.py."""
    names: set[str] = set()
    for rel in sources & trees.keys():
        tree = trees[rel]
        if tree is not None:
            names |= {PurePosixPath(n.value).name for n in ast.walk(tree)
                      if isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value.endswith(".py")}
    return {rel for rel in trees if PurePosixPath(rel).name in names} - sources


def _check_file(path: Path, rel: str, context: str, tree: ast.Module | None,
                top_level: str = "import") -> list[Finding]:
    lines = read_text(path).splitlines()
    if tree is not None:
        visitor = _Visitor(tree, rel, lines, context, top_level=top_level)
        try:
            visitor.visit(tree)
            return _combine(visitor.findings)
        except RecursionError:
            pass  # extremely deep nesting (also an evasion trick): fall back to text matching
    return _combine(_check_text(lines, rel, context or "call"))


def _check_pth(path: Path, rel: str) -> list[Finding]:
    """Every .pth line starting with "import" is executed by Python's site module at start-up."""
    lines = read_text(path).splitlines()
    findings: list[Finding] = []
    for number, line in enumerate(lines, 1):
        if line.startswith(("import ", "import\t")):
            tree = parse_text(line)
            if tree is None:
                continue
            visitor = _Visitor(tree, rel, lines, "startup", offset=number - 1)
            try:
                visitor.visit(tree)
            except RecursionError:
                continue
            findings += visitor.findings
    return _combine(findings)


def _finding(rule: str, rel: str, line: int, context: str, detail: str, lines: list[str]) -> Finding:
    evidence = lines[line - 1].strip()[:160] if 0 < line <= len(lines) else ""
    return Finding(rule, rel, line, context, _STRENGTH[rule][CONTEXTS.index(context)], detail, evidence)


def _combine(findings: list[Finding]) -> list[Finding]:
    """Credential theft and exfiltration need two parts in one file: something worth stealing (or a suspicious
    destination) and a network call. The combination is judged by when the network call runs."""
    real = [f for f in findings if f.context != "dev"]
    outgoing = [f for f in real if f.rule in ("network", "risky command")]
    if not outgoing:
        return findings
    sender = min(outgoing, key=lambda f: CONTEXTS.index(f.context))
    combined = list(findings)
    for rule, parts in (("secret + network", ("secret", "environment")), ("endpoint + network", ("endpoint",))):
        source = next((f for f in real if f.rule in parts), None)
        if source:
            detail = f"{source.detail} (line {source.line}), and uses the network (line {sender.line})"
            combined.append(Finding(rule, sender.path, source.line, sender.context,
                                    _STRENGTH[rule][CONTEXTS.index(sender.context)], detail, source.evidence))
    return combined


def _check_text(lines: list[str], rel: str, context: str) -> list[Finding]:
    """Fallback for files Python 3 cannot parse (often Python 2): plain-text matches, one level weaker."""
    found = []
    for number, line in enumerate(lines, 1):
        if line.lstrip().startswith("#"):
            continue
        hits = [(rule, f"{rule} (text match)") for rule, pattern in _TEXT_RULES if pattern.search(line)]
        hits += [(rule, f"{what} (text match)") for _, text in _QUOTED.findall(line) for rule, what in _check_string(text)]
        for rule, detail in hits:
            f = _finding(rule, rel, number, context, detail, lines)
            found.append(Finding(f.rule, f.path, f.line, f.context, _WEAKER[f.strength], f.detail, f.evidence))
    return found


def _check_string(text: str) -> list[tuple[str, str]]:
    low = text[:_MAX_STRING].lower()
    found = []
    for match in _URL.finditer(low):
        host, path = match.group(1).strip("[]"), match.group(2) or ""
        what = _endpoint_kind(host, path)
        if what:
            found.append(("short link" if what == "URL shortener" else "endpoint", what))
    found += [(rule, what) for pattern, rule, what in _STRING_RULES if pattern.search(low)]
    return found


def _endpoint_kind(host: str, path: str) -> str:
    if _is_public_ip(host):
        return "a URL that uses a raw public IP address"
    for (shady_host, prefix), what in _SHADY_PATHS.items():
        if host == shady_host and path.startswith(prefix):
            return what
    for shady_host, what in _SHADY_HOSTS.items():
        if host == shady_host or host.endswith(f".{shady_host}"):
            return what
    return ""


def _is_public_ip(text: str) -> bool:
    try:
        return ipaddress.ip_address(text).is_global
    except ValueError:
        return False


class _Visitor(ast.NodeVisitor):
    def __init__(self, tree: ast.Module, rel: str, lines: list[str], context: str, offset: int = 0,
                 nesting: int = 0, top_level: str = "import") -> None:
        self.rel, self.lines, self.fixed_context, self.offset, self.nesting = rel, lines, context, offset, nesting
        self.top_level = top_level  # "install" for a module that setup.py imports
        self.aliases = import_aliases(tree)
        self.scopes = [_scope_assignments(tree.body, self.aliases)]
        self.client_attributes = _client_attributes(tree, self.aliases)
        self.import_time = _import_time_functions(tree, self.aliases)
        self.skip = _comment_strings(tree)
        self.findings: list[Finding] = []
        self.function: str | None = None  # the module-level function being visited
        self.depth = 0
        self.classes = 0
        self.main_guard = False
        self.in_call = 0  # above 0 while visiting the arguments of a call

    def context(self) -> str:
        if self.fixed_context:
            return self.fixed_context
        if self.main_guard:
            return "call"  # runs only when the file is executed as a script
        if self.depth == 0 or self.function in self.import_time:
            return self.top_level
        return "call"

    def report(self, rule: str, node: ast.AST, detail: str, context: str | None = None) -> None:
        line = getattr(node, "lineno", 1) + self.offset
        self.findings.append(_finding(rule, self.rel, line, context or self.context(), detail, self.lines))

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.classes += 1
        self.generic_visit(node)
        self.classes -= 1

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda) -> None:
        outer, outer_calls = self.function, self.in_call
        if self.depth == 0 and self.classes == 0 and not isinstance(node, ast.Lambda):
            self.function = node.name
        elif self.depth == 0:
            self.function = None
        self.scopes.append(_scope_assignments([node.body] if isinstance(node, ast.Lambda) else node.body,
                                              self.aliases))
        self.depth += 1
        self.in_call = 0  # a function defined inside a call's arguments still runs later
        self.generic_visit(node)
        self.depth -= 1
        self.in_call = outer_calls
        self.scopes.pop()
        self.function = outer

    visit_AsyncFunctionDef = visit_FunctionDef
    visit_Lambda = visit_FunctionDef

    def visit_If(self, node: ast.If) -> None:
        if self.depth == 0 and _is_main_guard(node):
            self.main_guard = True
            for child in node.body:
                self.visit(child)
            self.main_guard = False
            for child in node.orelse:
                self.visit(child)
        else:
            self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = full_name(node.func, self.aliases)
        sends = self.network_call(node, name)
        if name in _EXEC_CALLS:
            self.check_exec(node, name)
        elif name in _PROCESS_CALLS:
            self.report("process", node, f"starts another program ({name})")
        elif sends:
            self.report("network", node, f"uses the network ({sends})")
        elif name in _ENV_READERS and node.args:
            self.check_env_name(node.args[0], node)
        if (sends or name in _ENV_SERIALIZERS) and self.whole_environment(node):
            self.report("environment", node, "collects every environment variable to send")
        if name.rpartition(".")[2] in _CONNECT_METHODS and node.args and isinstance(node.args[0], ast.Tuple):
            host = node.args[0].elts[0] if node.args[0].elts else None
            if isinstance(host, ast.Constant) and isinstance(host.value, str) and _is_public_ip(host.value):
                self.report("endpoint", node, "connects to a raw public IP address")
        self.visit(node.func)
        self.in_call += 1
        for child in [*node.args, *(k.value for k in node.keywords)]:
            self.visit(child)
        self.in_call -= 1

    def network_call(self, node: ast.Call, name: str) -> str:
        """What this call sends over the network, or "" when it sends nothing by itself (e.g. creating a socket)."""
        if name in _NETWORK_SENDS:
            return name
        if name in _CONNECT_ON_CREATE and (node.args or any(k.arg == "host" for k in node.keywords)):
            return name
        if not (isinstance(node.func, ast.Attribute) and node.func.attr in _TRAFFIC_METHODS):
            return ""
        receiver = node.func.value
        if isinstance(receiver, ast.Call):
            made_by = {full_name(receiver.func, self.aliases)}
        elif isinstance(receiver, ast.Name):
            made_by = self.assigned(receiver.id)
        elif isinstance(receiver, ast.Attribute):
            made_by = self.client_attributes.get(receiver.attr, set())
        else:
            return ""
        client = min((c for c in made_by if c in _NETWORK_CLIENTS), default="")
        return f"{client}(...).{node.func.attr}" if client else ""

    def whole_environment(self, node: ast.Call) -> bool:
        """os.environ itself, dict(os.environ) or os.environ.copy() is passed in; .get("X") reads only one."""
        reads_one: set[int] = set()
        environs: list[int] = []
        for part in [*node.args, *(k.value for k in node.keywords)]:
            for n in ast.walk(part):
                if isinstance(n, ast.Call) and full_name(n.func, self.aliases) in _ENV_WHOLE:
                    return True
                if isinstance(n, (ast.Attribute, ast.Subscript)):
                    reads_one.add(id(n.value))
                if isinstance(n, (ast.Attribute, ast.Name)) and full_name(n, self.aliases) == "os.environ":
                    environs.append(id(n))
        return any(i not in reads_one for i in environs)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if full_name(node.value, self.aliases) == "os.environ":
            self.check_env_name(node.slice, node)
        self.generic_visit(node)

    def check_env_name(self, key: ast.AST, node: ast.AST) -> None:
        if isinstance(key, ast.Constant) and isinstance(key.value, str) and _CREDENTIAL_ENV.fullmatch(key.value):
            self.report("secret", node, f"reads a credential from the environment ({key.value})")

    def check_exec(self, node: ast.Call, name: str) -> None:
        args = [*node.args, *(k.value for k in node.keywords)]
        if not args:
            return
        calls = {full_name(n.func, self.aliases) for arg in args for n in ast.walk(arg) if isinstance(n, ast.Call)}
        for arg in args:
            for n in ast.walk(arg):
                if isinstance(n, ast.Name):
                    calls |= self.assigned(n.id)
        if any(c.startswith(_DECODERS) or c in _NETWORK_SENDS or c in _NETWORK_CLIENTS for c in calls):
            self.report("decoded exec", node, f"runs code that is decoded or downloaded while running ({name})")
        elif isinstance(args[0], ast.Constant) and isinstance(args[0].value, (str, bytes)):
            self.skip.add(id(args[0]))
            code = args[0].value
            self.check_inner_code(code.decode("latin-1") if isinstance(code, bytes) else code, node)
        elif not any(c in _FILE_READERS or c.endswith(_READ_METHODS) for c in calls):
            self.report("exec", node, f"runs code built while running ({name})")

    def assigned(self, name: str) -> set[str]:
        """Calls behind a variable, following chains like b = a; a = b64decode(x). Looked up the way Python does:
        the current function first, then the module."""
        calls: set[str] = set()
        seen: set[str] = set()
        todo = [name]
        while todo and len(seen) < 50:
            var = todo.pop()
            if var in seen:
                continue
            seen.add(var)
            scope = self.scopes[-1] if var in self.scopes[-1] else self.scopes[0]
            var_calls, var_names = scope.get(var, (set(), set()))
            calls |= var_calls
            todo += var_names
        return calls

    def check_inner_code(self, code: str, node: ast.AST) -> None:
        """exec("...") runs the code inside the string, so that code is checked too, at the exec line."""
        tree = parse_text(code) if self.nesting < _MAX_NESTING else None
        if tree is None:
            return
        inner = _Visitor(tree, self.rel, self.lines, self.context(), self.offset, self.nesting + 1)
        inner.visit(tree)
        line = getattr(node, "lineno", 1) + self.offset
        self.findings += [Finding(f.rule, f.path, line, f.context, f.strength, f"{f.detail} inside a code string",
                                  self.lines[line - 1].strip()[:160] if 0 < line <= len(self.lines) else f.evidence)
                          for f in inner.findings]

    def visit_Constant(self, node: ast.Constant) -> None:
        if id(node) in self.skip:
            return
        value = node.value.decode("latin-1") if isinstance(node.value, bytes) else node.value
        if isinstance(value, str) and len(value) >= 4:
            context = self.context()
            if not self.in_call and context not in ("dev", "startup"):
                context = "call"  # a value that is only stored here; the code that uses it is judged where it runs
            for rule, what in _check_string(value):
                verb = "mentions" if rule in ("secret", "persistence", "risky command") else "points to"
                self.report(rule, node, f"{verb} {what}", context)


def _is_main_guard(node: ast.If) -> bool:
    """if __name__ == "__main__":, alone or combined with other conditions using `and`."""
    test = node.test
    tests = test.values if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And) else [test]
    return any(isinstance(t, ast.Compare) and len(t.comparators) == 1 and isinstance(t.ops[0], ast.Eq)
               and {_name_or_value(t.left), _name_or_value(t.comparators[0])} == {"__name__", "__main__"}
               for t in tests)


def _name_or_value(node: ast.AST) -> object:
    if isinstance(node, ast.Name):
        return node.id
    return node.value if isinstance(node, ast.Constant) else None


def _comment_strings(tree: ast.Module) -> set[int]:
    """Docstrings and other bare string statements are documentation, not behaviour."""
    return {id(node.value) for node in ast.walk(tree)
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)}


def _scope_assignments(body: list[ast.AST], aliases: dict[str, str]) -> dict[str, tuple[set[str], set[str]]]:
    """Variable -> (calls, variables) used to compute it, within one scope; nested functions have their own."""
    assigned: dict[str, tuple[set[str], set[str]]] = {}

    def record(target: ast.AST, value: ast.AST) -> None:
        parts = list(ast.walk(value))
        calls = {full_name(n.func, aliases) for n in parts if isinstance(n, ast.Call)}
        names = {n.id for n in parts if isinstance(n, ast.Name)}
        for n in ast.walk(target):
            if isinstance(n, ast.Name):
                var_calls, var_names = assigned.setdefault(n.id, (set(), set()))
                var_calls |= calls
                var_names |= names - {n.id}

    stack = list(body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            continue
        if isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign, ast.NamedExpr)) and node.value is not None:
            for target in node.targets if isinstance(node, ast.Assign) else [node.target]:
                record(target, node.value)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:  # with requests.Session() as s:
                    record(item.optional_vars, item.context_expr)
        stack.extend(ast.iter_child_nodes(node))
    return assigned


def _client_attributes(tree: ast.Module, aliases: dict[str, str]) -> dict[str, set[str]]:
    """Attribute name -> network clients assigned to it anywhere in the file: self.session = requests.Session()."""
    found: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            clients = {full_name(n.func, aliases) for n in ast.walk(node.value) if isinstance(n, ast.Call)}
            clients &= _NETWORK_CLIENTS
            for target in node.targets if isinstance(node, ast.Assign) else [node.target]:
                if clients and isinstance(target, ast.Attribute):
                    found.setdefault(target.attr, set()).update(clients)
    return found


def _import_time_functions(tree: ast.Module, aliases: dict[str, str]) -> set[str]:
    """Module-level functions that run at import: called by top-level code (directly or through each other), handed
    to something that runs them (Thread(target=f), atexit.register(f)), or decorated with @atexit.register.
    Merely naming a function, or passing it to an arbitrary call as a callback, does not run it."""
    functions = {n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    top = [n for n in tree.body if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
           and not (isinstance(n, ast.If) and _is_main_guard(n))]

    def used(nodes: list[ast.AST]) -> set[str]:
        found = set()
        for node in nodes:
            for n in ast.walk(node):
                if isinstance(n, ast.Call):
                    handed = [*n.args, *(k.value for k in n.keywords)] if full_name(n.func, aliases) in _SCHEDULERS else []
                    found |= {c.id for c in (n.func, *handed) if isinstance(c, ast.Name) and c.id in functions}
        return found

    scheduled = {name for name, f in functions.items()
                 if any(full_name(d, aliases) in _SCHEDULERS for d in f.decorator_list)}
    todo, done = used(top) | scheduled, set()
    while todo:
        name = todo.pop()
        done.add(name)
        todo |= used(functions[name].body) - done
    return done
