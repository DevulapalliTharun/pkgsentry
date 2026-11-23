from pathlib import Path

from pkgsentry import cli
from pkgsentry.cli import _printable, format_code, format_fetch, format_scan, main
from pkgsentry.analyzers.rules import Finding
from pkgsentry.models import PackageInfo, ReleaseFile
from pkgsentry.pipeline import Analysis
from pkgsentry.scoring import RiskReport, RiskSignal
from pkgsentry.fetch.extract import ExtractionReport
from pkgsentry.models import ReleaseFile


def test_printable_neutralises_terminal_control_characters():
    assert _printable("evil\x1b[2Jname\r\n") == "evil?[2Jname??"
    assert _printable("Árfigyelő-api") == "Árfigyelő-api"


def test_format_fetch_shows_refused_entries_safely(tmp_path):
    file = ReleaseFile("demo-1.0.tar.gz", "sdist", "https://files.pythonhosted.org/x", 2048, "ab" * 32, None)
    report = ExtractionReport(root=tmp_path, files=["demo-1.0/setup.py"], bytes_written=100,
                              skipped=[("../\x1b[31mevil", "path traversal (..)")])
    text = format_fetch(file, tmp_path / "demo-1.0.tar.gz", report)
    assert "Refused     1 suspicious entries" in text
    assert "\x1b" not in text
    assert "Nothing was installed or run." in text


def test_format_code_shows_obfuscation_findings():
    finding = Finding("invisible unicode", "demo/setup.py", 4, "install", "medium",
                      "contains invisible formatting characters: U+202E RIGHT-TO-LEFT OVERRIDE", "name = 'evil'")
    text = format_code("demo 1.0 (sdist)", [finding])
    assert "invisible unicode" in text
    assert "medium" in text and "setup.py:4" in text


def test_format_scan_shows_score_evidence_and_defangs_urls(tmp_path):
    package = PackageInfo("demo", "1.0", "", "", "", "", 0, 1, None, ())
    file = ReleaseFile("demo-1.0.tar.gz", "sdist", "https://files.pythonhosted.org/x", 100,
                       "ab" * 32, None)
    extraction = ExtractionReport(root=tmp_path, files=["demo-1.0/setup.py"], bytes_written=50)
    report = RiskReport(42, "high", (RiskSignal("code", 30, "strong", "install",
                                                "sends data to https://evil.example/x", "setup.py", 8),))
    text = format_scan(package, file, tmp_path / "demo-1.0.tar.gz", extraction, report)
    assert "Risk score  42/100  HIGH" in text
    assert "+30  code" in text and "setup.py:8" in text
    assert "hxxps://evil[.]example/x" in text and "https://evil.example" not in text
    assert text.endswith("Nothing was installed or run.")


def test_scan_command_runs_all_analyzers_without_network(tmp_path, monkeypatch, capsys):
    package = PackageInfo("demo", "1.0", "summary", "author", "a@example.org", "https://example.org",
                          500, 4, None, ())
    file = ReleaseFile("demo-1.0.tar.gz", "sdist", "https://files.pythonhosted.org/x", 100,
                       "ab" * 32, None)
    extraction = ExtractionReport(root=tmp_path, files=[], bytes_written=0)
    monkeypatch.setattr(cli, "_fetch", lambda args: (package, file, tmp_path / file.filename, extraction))
    monkeypatch.setattr(cli, "analyze", lambda root, pkg, kind: Analysis([], [], RiskReport(0, "low", ()), [], []))
    assert main(["scan", "demo"]) == 0
    assert "Risk score  0/100  LOW" in capsys.readouterr().out


def test_check_name_command(capsys):
    assert main(["check-name", "reqeusts", "requests"]) == 0
    out = capsys.readouterr().out
    assert "strong" in out and "swapped letters" in out
    assert "A popular package itself" in out


def test_check_name_rejects_invalid_names(capsys):
    assert main(["check-name", "../etc/passwd"]) == 1
    assert "error:" in capsys.readouterr().err
