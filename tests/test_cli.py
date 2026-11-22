from pathlib import Path

from pkgsentry.cli import _printable, format_fetch, main
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


def test_check_name_command(capsys):
    assert main(["check-name", "reqeusts", "requests"]) == 0
    out = capsys.readouterr().out
    assert "strong" in out and "swapped letters" in out
    assert "A popular package itself" in out


def test_check_name_rejects_invalid_names(capsys):
    assert main(["check-name", "../etc/passwd"]) == 1
    assert "error:" in capsys.readouterr().err
