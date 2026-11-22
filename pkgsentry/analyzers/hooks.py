"""Find package code that runs without anyone calling it: when pip prepares or installs the package, every time
Python starts, or when a familiar command is typed. Files are only read and parsed, never imported or run."""

import ast
import configparser
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from pkgsentry.analyzers.source import dotted, full_name, import_aliases, parse_source, read_text
from pkgsentry.analyzers.typosquat import Popular, check_name, normalize

# setuptools steps a package can replace (cmdclass): when pip runs each one, and how unusual replacing it is.
_STEPS = {
    "egg_info": ("download", "medium"),
    "dist_info": ("download", "medium"),
    "install": ("install", "medium"),
    "install_lib": ("install", "medium"),
    "install_scripts": ("install", "medium"),
    "install_data": ("install", "medium"),
    "build": ("install", "weak"),
    "build_py": ("install", "weak"),
    "build_ext": ("install", "weak"),
    "build_clib": ("install", "weak"),
    "build_scripts": ("install", "weak"),
    "bdist_wheel": ("install", "weak"),
    "develop": ("editable install", "weak"),
    "editable_wheel": ("editable install", "weak"),
}
_RUNS = {
    "download": "even on 'pip download'",
    "install": "when pip builds or installs the package",
    "editable install": "only for editable installs of the source",
}
# Everyday commands, and the one package allowed to install each (None: no PyPI package should).
_COMMAND_OWNERS: dict[str, str | None] = {
    **dict.fromkeys([
        "bash", "sh", "zsh", "ls", "cat", "cp", "mv", "rm", "chmod", "chown", "sudo", "su", "ssh", "scp", "curl",
        "wget", "git", "env", "which", "ps", "kill", "ping", "open", "grep", "find", "tar", "gpg", "python",
        "docker", "kubectl", "brew", "apt", "apt-get", "yum",
    ]),
    "pip": "pip", "pytest": "pytest", "ipython": "ipython", "jupyter": "jupyter-core", "aws": "awscli",
    "az": "azure-cli", "uv": "uv", "poetry": "poetry", "twine": "twine", "black": "black", "ruff": "ruff",
    "flake8": "flake8", "mypy": "mypy", "tox": "tox", "virtualenv": "virtualenv", "pipx": "pipx",
    "django-admin": "django", "flask": "flask", "celery": "celery", "gunicorn": "gunicorn", "uvicorn": "uvicorn",
}
_SETUP_FUNCTIONS = {"setup", "setuptools.setup", "distutils.core.setup"}
_STEP_MODULES = ("setuptools.", "distutils.", "wheel.")
_STARTUP_MODULES = {"sitecustomize.py", "usercustomize.py", "sitecustomize/__init__.py", "usercustomize/__init__.py"}
_STRENGTH_ORDER = {"strong": 0, "medium": 1, "weak": 2, "info": 3}
_REQUIREMENT_NAME = re.compile(r"\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)")
_EXTRA_MARKER = re.compile(r";.*\bextra\s*==")  # optional extras install only when asked for by name
_VERSIONED = re.compile(r"(python|pip)[\d.]*")  # python3.14 -> python, pip3 -> pip


@dataclass(frozen=True)
class Hook:
    when: str  # "download", "install", "editable install", "startup" or "command"
    kind: str
    path: str  # inside the unpacked folder, "/"-separated
    line: int  # 0 when the whole file applies
    detail: str
    strength: str  # "strong", "medium", "weak" or "info"


def find_hooks(root: Path, package: str, kind: str, popular: tuple[Popular, ...] | None = None) -> list[Hook]:
    """kind is "sdist" or "wheel", taken from PyPI: the archive's own layout is attacker-controlled."""
    scan = _Scan(root, package, kind == "wheel", popular)
    scan.run()
    return sorted(scan.hooks, key=lambda h: (_STRENGTH_ORDER[h.strength], h.when, h.path, h.line))


class _Scan:
    def __init__(self, root: Path, package: str, wheel: bool, popular: tuple[Popular, ...] | None) -> None:
        self.files = {p.relative_to(root).as_posix(): p for p in sorted(root.rglob("*")) if p.is_file()}
        self.package = normalize(package)
        self.popular = popular
        self.wheel = wheel
        self.top = "" if wheel else single_top_folder(self.files)  # an sdist unpacks into "name-version/"
        self.hooks: list[Hook] = []
        self.commands: dict[str, str] = {}  # command -> file that declares it
        self.requirements: dict[str, tuple[str, str]] = {}  # normalized name -> (name, file)
        self.build_requirements: dict[str, tuple[str, str]] = {}

    def add(self, when: str, kind: str, path: str, line: int, detail: str, strength: str) -> None:
        self.hooks.append(Hook(when, kind, path, line, detail, strength))

    def run(self) -> None:
        if not self.wheel:
            if f"{self.top}setup.py" in self.files:
                self.setup_py(f"{self.top}setup.py")
            if f"{self.top}setup.cfg" in self.files:
                self.setup_cfg(f"{self.top}setup.cfg")
            if f"{self.top}pyproject.toml" in self.files:
                self.pyproject(f"{self.top}pyproject.toml")
        for rel, path in self.files.items():
            self.metadata_file(rel, path)
            self.startup_file(rel, path)
        self.check_commands()
        self.check_requirements()

    def setup_py(self, rel: str) -> None:
        self.add("download", "setup.py", rel, 0,
                 "pip runs this whole file to learn the package's details, even for 'pip download'", "info")
        tree = parse_source(self.files[rel])
        if tree is None:
            self.add("download", "unreadable setup.py", rel, 0,
                     "not valid Python 3 (or over 5 MB), so it cannot be checked without running it", "weak")
            return
        aliases = import_aliases(tree)
        assigned = {target.id: node.value for node in tree.body if isinstance(node, ast.Assign)
                    for target in node.targets if isinstance(target, ast.Name)}
        keywords = _setup_keywords(tree, aliases, assigned)
        cmdclass = _resolve(keywords.get("cmdclass"), assigned)
        for code, (step, line) in _command_classes(tree, aliases, cmdclass).items():
            self.step_hook(step, rel, line, code)
        if isinstance(cmdclass, ast.Call) and not _keyword_dict(cmdclass):
            self.add("download", "custom steps computed at run time", rel, cmdclass.lineno,
                     f"cmdclass comes from {dotted(cmdclass.func) or 'a function call'}(), so the steps it replaces "
                     f"cannot be listed without running setup.py", "info")
        loaded = set()
        for name in sorted(set(aliases.values())):
            parts = name.split(".")  # importing a.b.c runs a/__init__.py, a/b/__init__.py and a/b/c.py
            for folder in (self.top, f"{self.top}src/"):
                for i in range(1, len(parts) + 1):
                    sub = "/".join(parts[:i])
                    loaded |= {c for c in (f"{folder}{sub}.py", f"{folder}{sub}/__init__.py") if c in self.files}
        for candidate in sorted(loaded - {rel}):
            self.add("download", "module run by setup.py", candidate, 0,
                     "setup.py imports this module, so it runs whenever setup.py does", "info")
        for command in _entry_point_names(_literal(keywords.get("entry_points"), assigned)):
            self.commands.setdefault(command, rel)
        for script in _strings(keywords.get("scripts"), assigned):
            self.commands.setdefault(PurePosixPath(script).name, rel)
        for name in _data_file_names(_literal(keywords.get("data_files"), assigned)):
            self.pth_data_file(name, rel, keywords["data_files"].lineno)
        for requirement in _strings(keywords.get("install_requires"), assigned):
            self.require(self.requirements, requirement, rel)
        for requirement in _strings(keywords.get("setup_requires"), assigned):
            self.require(self.build_requirements, requirement, rel)

    def step_hook(self, step: str, rel: str, line: int, code: str) -> None:
        when, strength = _STEPS[step]
        self.add(when, f"custom '{step}' step", rel, line,
                 f"{code} replaces setuptools' '{step}' step, so its code runs {_RUNS[when]}", strength)

    def pth_data_file(self, name: str, rel: str, line: int) -> None:
        if name.endswith(".pth"):
            self.add("install", ".pth file installed as data", rel, line,
                     f"installs '{name}' as a data file; if it lands in site-packages, its import lines run at every "
                     f"Python start", "medium")

    def setup_cfg(self, rel: str) -> None:
        parser = configparser.ConfigParser(interpolation=None, strict=False)
        try:
            parser.read_string(read_text(self.files[rel]))
        except configparser.Error:
            return
        options = parser["options"] if parser.has_section("options") else {}
        for line in options.get("cmdclass", "").splitlines():
            step, _, target = (part.strip() for part in line.partition("="))
            if step in _STEPS:
                self.step_hook(step, rel, 0, target)
        for line in options.get("install_requires", "").splitlines():
            self.require(self.requirements, line, rel)
        for line in options.get("setup_requires", "").splitlines():
            self.require(self.build_requirements, line, rel)
        entry_points = parser["options.entry_points"] if parser.has_section("options.entry_points") else {}
        for group in ("console_scripts", "gui_scripts"):
            for line in entry_points.get(group, "").splitlines():
                if "=" in line:
                    self.commands.setdefault(line.split("=", 1)[0].strip(), rel)

    def pyproject(self, rel: str) -> None:
        try:
            data = tomllib.loads(read_text(self.files[rel]))
        except (ValueError, RecursionError):
            return  # pip refuses to build a package whose pyproject.toml is invalid
        build = _table(data.get("build-system"))
        backend, paths = build.get("build-backend"), _str_list(build.get("backend-path"))
        if paths and isinstance(backend, str):
            module = backend.split(":")[0].replace(".", "/")
            candidates = [f"{self.top}{PurePosixPath(p, module)}{end}" for p in paths for end in (".py", "/__init__.py")]
            self.add("download", "in-tree build backend", next((c for c in candidates if c in self.files), rel), 0,
                     f"pip builds this package with its own build code ('{backend}'), even for 'pip download'", "info")
        for requirement in _str_list(build.get("requires")):
            self.require(self.build_requirements, requirement, rel)
        self.build_tool_hooks(data, backend)
        project = _table(data.get("project"))
        for group in ("scripts", "gui-scripts"):
            for command in _table(project.get(group)):
                self.commands.setdefault(command, rel)
        for requirement in _str_list(project.get("dependencies")):
            self.require(self.requirements, requirement, rel)
        setuptools = _table(_table(data.get("tool")).get("setuptools"))
        for step, target in _table(setuptools.get("cmdclass")).items():
            if step in _STEPS:
                self.step_hook(step, rel, 0, str(target))
        for script in _str_list(setuptools.get("script-files")):
            self.commands.setdefault(PurePosixPath(script).name, rel)
        for files in _table(setuptools.get("data-files")).values():
            for name in _str_list(files):
                self.pth_data_file(PurePosixPath(name).name, rel, 0)

    def build_tool_hooks(self, data: dict, backend: object) -> None:
        """Build tools that run a Python file of the package while building it: hatchling custom hooks
        (hatch_build.py by default), pdm-backend (pdm_build.py) and Poetry build scripts."""
        tool = _table(data.get("tool"))
        hatch = _table(tool.get("hatch"))
        build = _table(hatch.get("build"))
        found: list[tuple[object, str]] = []
        for hooks in [_table(build.get("hooks")), *(_table(_table(t).get("hooks"))
                                                    for t in _table(build.get("targets")).values())]:
            if "custom" in hooks:
                found.append((_table(hooks["custom"]).get("path", "hatch_build.py"), "install"))
        metadata_hooks = _table(_table(hatch.get("metadata")).get("hooks"))
        if "custom" in metadata_hooks:
            found.append((_table(metadata_hooks["custom"]).get("path", "hatch_build.py"), "download"))
        if isinstance(backend, str) and backend.startswith("pdm.backend"):
            found.append(("pdm_build.py", "install"))
        poetry_build = _table(tool.get("poetry")).get("build")
        found.append((_table(poetry_build).get("script") if isinstance(poetry_build, dict) else poetry_build, "install"))
        for path, when in found:
            candidate = f"{self.top}{PurePosixPath(path)}" if isinstance(path, str) else ""
            if candidate in self.files:
                self.add(when, "custom build hook", candidate, 0,
                         f"the build tool runs this file while building the package"
                         f"{', even for pip download' if when == 'download' else ''}", "info")

    def metadata_file(self, rel: str, path: Path) -> None:
        parts = PurePosixPath(rel).parts
        if self.wheel:
            if len(parts) == 2 and parts[0].endswith(".dist-info"):
                self.metadata(parts[1], rel, path)
            elif len(parts) == 3 and parts[0].endswith(".data") and parts[1] == "scripts":
                self.commands.setdefault(parts[2], rel)
            return
        inner = parts[1:] if self.top else parts
        if inner == ("PKG-INFO",):
            self.metadata("METADATA", rel, path)
        elif len(inner) in (2, 3) and inner[-2].endswith(".egg-info") and (len(inner) == 2 or inner[0] == "src"):
            self.metadata(inner[-1], rel, path)

    def metadata(self, name: str, rel: str, path: Path) -> None:
        if name == "METADATA":
            for requirement in _requires_dist(read_text(path)):
                self.require(self.requirements, requirement, rel)
        elif name == "requires.txt":
            optional = False
            for line in read_text(path).splitlines():
                if line.startswith("["):
                    optional = not line.startswith("[:")  # "[extra]" starts optional extras; "[:marker]" does not
                elif not optional and line.strip() and not line.lstrip().startswith("#"):
                    self.require(self.requirements, line, rel)
        elif name == "entry_points.txt":
            for command in _ini_commands(read_text(path)):
                self.commands.setdefault(command, rel)

    def startup_file(self, rel: str, path: Path) -> None:
        site = self.site_path(rel)
        if site is None:
            return
        # A wheel's top level is copied into site-packages; an sdist's files get there only if setup.py says so.
        certain = self.wheel
        if site.endswith(".pth") and "/" not in site:
            for number, line in enumerate(read_text(path).splitlines(), 1):
                if line.startswith(("import ", "import\t")):
                    where = "Python runs" if certain else "If this file is installed into site-packages, Python runs"
                    self.add("startup", ".pth startup code", rel, number,
                             f"{where} this line at every start: {line.strip()[:80]}", "medium" if certain else "weak")
                    break
        elif site in _STARTUP_MODULES:
            module = site.split("/")[0].removesuffix(".py")
            where = "Python imports" if certain else "If this module is installed, Python imports"
            self.add("startup", "startup module", rel, 0, f"{where} '{module}' automatically at every start",
                     "strong" if certain else "medium")

    def site_path(self, rel: str) -> str | None:
        """Where a file lands relative to site-packages once installed (None for scripts and other data)."""
        if not self.wheel:
            return rel.removeprefix(self.top).removeprefix("src/")
        parts = PurePosixPath(rel).parts
        if parts[0].endswith(".data"):
            return "/".join(parts[2:]) if len(parts) > 2 and parts[1] in ("purelib", "platlib") else None
        return rel

    def require(self, store: dict[str, tuple[str, str]], requirement: str, rel: str) -> None:
        match = _REQUIREMENT_NAME.match(requirement)
        if match and normalize(match.group(1)) != self.package and not _EXTRA_MARKER.search(requirement):
            store.setdefault(normalize(match.group(1)), (match.group(1), rel))

    def check_commands(self) -> None:
        for command, rel in self.commands.items():
            key = command.lower()
            if versioned := _VERSIONED.fullmatch(key):
                key = versioned.group(1)
            if key not in _COMMAND_OWNERS or _COMMAND_OWNERS[key] == self.package:
                continue
            owner = _COMMAND_OWNERS[key]
            detail = (f"installs a command named '{command}', which normally comes from the '{owner}' package"
                      if owner else f"installs a command named '{command}' that would run instead of the system's "
                                    f"'{key}'")
            self.add("command", "command-jacking", rel, 0, detail, "strong")

    def check_requirements(self) -> None:
        for store, when, what in ((self.build_requirements, "download", "build requirement"),
                                  (self.requirements, "install", "dependency")):
            for name, rel in store.values():
                result = check_name(name, self.popular)
                # An author picks dependencies on purpose, so only near-certain look-alikes are reported.
                close = [m for m in result.matches if m.strength == "strong"]
                if close:
                    m = close[0]
                    self.add(when, f"{what} looks like a typosquat", rel, 0,
                             f"'{name}' looks like '{m.target.name}' (#{m.target.rank:,}): {m.technique}", m.strength)
                elif what == "build requirement" and result.popular is None:
                    self.add(when, "uncommon build requirement", rel, 0,
                             f"'{name}' is not a popular package, yet pip installs it and runs its code to build this "
                             f"one", "weak")


def single_top_folder(files: dict[str, Path]) -> str:
    tops = {rel.split("/")[0] for rel in files}
    return f"{tops.pop()}/" if len(tops) == 1 and all("/" in rel for rel in files) else ""


def _table(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _str_list(value: object) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _resolve(node: ast.AST | None, assigned: dict[str, ast.AST]) -> ast.AST | None:
    return assigned.get(node.id, node) if isinstance(node, ast.Name) else node


def _keyword_dict(node: ast.AST | None) -> dict[str, ast.AST]:
    """{"a": x} or dict(a=x) -> {"a": node of x}."""
    if isinstance(node, ast.Dict):
        return {k.value: v for k, v in zip(node.keys, node.values)
                if isinstance(k, ast.Constant) and isinstance(k.value, str)}
    if isinstance(node, ast.Call) and dotted(node.func) == "dict":
        return {k.arg: k.value for k in node.keywords if k.arg}
    return {}


def _setup_keywords(tree: ast.Module, aliases: dict[str, str], assigned: dict[str, ast.AST]) -> dict[str, ast.AST]:
    keywords: dict[str, ast.AST] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and full_name(node.func, aliases) in _SETUP_FUNCTIONS:
            for keyword in node.keywords:
                if keyword.arg:
                    keywords.setdefault(keyword.arg, keyword.value)
                else:  # setup(**options)
                    keywords = _keyword_dict(_resolve(keyword.value, assigned)) | keywords
    return keywords


def _command_classes(tree: ast.Module, aliases: dict[str, str], cmdclass: ast.AST | None) -> dict[str, tuple[str, int]]:
    """What replaces a setuptools step -> (step, line). A literal cmdclass is the authority; without one, every
    subclass of a setuptools step counts, because it might be registered in a way we cannot read."""
    subclasses: dict[str, tuple[str, int]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for base in node.bases:
                full = full_name(base, aliases)
                step = subclasses[full][0] if full in subclasses else full.rpartition(".")[2]
                if (full in subclasses or full.startswith(_STEP_MODULES)) and step in _STEPS:
                    subclasses[node.name] = (step, node.lineno)
                    break
    registered = _keyword_dict(cmdclass)
    if not registered:
        return {f"class {name}": found for name, found in subclasses.items()}
    defined = {node.name: node.lineno for node in ast.walk(tree) if isinstance(node, ast.ClassDef)}
    found: dict[str, tuple[str, int]] = {}
    for step, value in registered.items():
        if step not in _STEPS:
            continue  # an extra command such as "python setup.py verify"; pip never runs it
        if isinstance(value, ast.Call):
            found[f"a class built by {dotted(value.func) or 'a function'}()"] = (step, value.lineno)
            continue
        name = dotted(value)
        if name in defined:
            found[f"class {name}"] = (step, defined[name])
        elif not full_name(value, aliases).startswith(_STEP_MODULES):
            found[f"{name or 'a class'} (defined outside setup.py)"] = (step, value.lineno)
    return found


def _literal(node: ast.AST | None, assigned: dict[str, ast.AST]) -> object:
    if node is None:
        return None
    try:
        return ast.literal_eval(_resolve(node, assigned))
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        return None


def _strings(node: ast.AST | None, assigned: dict[str, ast.AST]) -> list[str]:
    value = _literal(node, assigned)
    if isinstance(value, str):
        return value.splitlines()
    if isinstance(value, dict):  # extras_require = {"extra": [...]}
        value = [item for group in value.values() for item in (group if isinstance(group, (list, tuple)) else [group])]
    return [item for item in value if isinstance(item, str)] if isinstance(value, (list, tuple, set)) else []


def _data_file_names(value: object) -> list[str]:
    """data_files=[("folder", ["a.pth", ...]), ...] -> ["a.pth", ...]."""
    names: list[str] = []
    for item in value if isinstance(value, (list, tuple)) else []:
        files = item[1] if isinstance(item, (list, tuple)) and len(item) == 2 else [item]
        if isinstance(files, (list, tuple)):
            names += [PurePosixPath(f).name for f in files if isinstance(f, str)]
    return names


def _entry_point_names(value: object) -> list[str]:
    if isinstance(value, str):
        return _ini_commands(value)
    names: list[str] = []
    if isinstance(value, dict):
        for group in ("console_scripts", "gui_scripts"):
            items = value.get(group, [])
            items = items.splitlines() if isinstance(items, str) else items
            if isinstance(items, (list, tuple)):
                names += [item.split("=", 1)[0].strip() for item in items if isinstance(item, str) and "=" in item]
    return names


def _ini_commands(text: str) -> list[str]:
    parser = configparser.ConfigParser(interpolation=None, delimiters=("=",), strict=False)
    parser.optionxform = str  # command names are case-sensitive
    try:
        parser.read_string(text)
    except configparser.Error:
        return []
    return [name for group in ("console_scripts", "gui_scripts") if parser.has_section(group) for name in parser[group]]


def _requires_dist(text: str) -> list[str]:
    found = []
    for line in text.splitlines():
        if not line:
            break  # the headers end at the first empty line; the free-text description follows
        if line.lower().startswith("requires-dist:"):
            found.append(line.split(":", 1)[1])
    return found
