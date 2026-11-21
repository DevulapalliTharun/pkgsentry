import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from pkgsentry.cli import format_info
from pkgsentry.fetch.pypi import parse_package, validate_name, validate_version

FIXTURE = Path(__file__).parent / "fixtures" / "demo_project.json"


@pytest.fixture
def package():
    data = json.loads(FIXTURE.read_text())
    return parse_package(data, data["releases"])


def test_basic_fields(package):
    assert package.name == "demo-pkg"
    assert package.version == "2.0.0"
    assert package.author_email == "Demo Author <demo@example.com>"
    assert package.homepage == "https://example.com/demo-pkg"


def test_release_history_ignores_versions_without_files(package):
    assert package.release_count == 2
    assert package.first_upload == datetime(2023, 1, 15, 8, 0, tzinfo=timezone.utc)


def test_files(package):
    assert [f.kind for f in package.files] == ["sdist", "wheel"]
    assert package.files[0].sha256.startswith("1111")
    assert package.has_wheel
    assert package.uploaded == datetime(2024, 3, 2, 10, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize("name", ["requests", "python-dateutil", "zope.interface", "a"])
def test_accepts_valid_names(name):
    assert validate_name(name) == name


@pytest.mark.parametrize("name", ["", "../admin", "evil?x=1", "a b", "-leading", "trailing-", "a/b"])
def test_rejects_names_that_could_change_the_url(name):
    with pytest.raises(ValueError):
        validate_name(name)


@pytest.mark.parametrize("version", ["../1.0", "1.0?x", ""])
def test_rejects_bad_versions(version):
    with pytest.raises(ValueError):
        validate_version(version)


def test_format_info_shows_key_facts(package):
    text = format_info(package)
    assert "demo-pkg 2.0.0" in text
    assert "Releases:      2 (first upload 2023-01-15)" in text
    assert "sdist" in text and "wheel" in text
