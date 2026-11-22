import hashlib

import pytest

from pkgsentry.fetch import download
from pkgsentry.fetch.download import IntegrityError, download_file
from pkgsentry.fetch.pypi import PyPIError
from pkgsentry.models import ReleaseFile

DATA = b"pretend this is a package archive" * 10


class FakeResponse:
    def __init__(self, data: bytes, status_code: int = 200):
        self.data = data
        self.status_code = status_code

    def iter_content(self, chunk_size):
        for i in range(0, len(self.data), chunk_size):
            yield self.data[i:i + chunk_size]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def release_file(sha256: str = hashlib.sha256(DATA).hexdigest(), **overrides) -> ReleaseFile:
    fields = dict(filename="demo-1.0.tar.gz", packagetype="sdist", size=len(DATA), sha256=sha256,
                  url="https://files.pythonhosted.org/packages/ab/cd/demo-1.0.tar.gz", upload_time=None)
    fields.update(overrides)
    return ReleaseFile(**fields)


@pytest.fixture
def served(monkeypatch):
    calls = []

    def fake_get(url, **kwargs):
        calls.append((url, kwargs))
        return FakeResponse(DATA)

    monkeypatch.setattr(download.requests, "get", fake_get)
    return calls


def test_downloads_and_verifies_sha256(tmp_path, served):
    path = download_file(release_file(), tmp_path)
    assert path.read_bytes() == DATA
    assert list(tmp_path.iterdir()) == [path]
    assert served[0][1]["allow_redirects"] is False


def test_rejects_a_hash_mismatch_and_leaves_nothing_behind(tmp_path, served):
    with pytest.raises(IntegrityError, match="mismatch"):
        download_file(release_file(sha256="0" * 64), tmp_path)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("url", [
    "https://evil.example/demo-1.0.tar.gz",
    "http://files.pythonhosted.org/demo-1.0.tar.gz",
    "https://files.pythonhosted.org.evil.example/demo-1.0.tar.gz",
])
def test_refuses_untrusted_locations(tmp_path, served, url):
    with pytest.raises(PyPIError, match="untrusted location"):
        download_file(release_file(url=url), tmp_path)
    assert served == []


def test_refuses_unsafe_file_names(tmp_path, served):
    with pytest.raises(PyPIError, match="unsafe file name"):
        download_file(release_file(filename="../demo-1.0.tar.gz"), tmp_path)


def test_stops_oversized_downloads(tmp_path, served):
    with pytest.raises(PyPIError, match="larger than"):
        download_file(release_file(), tmp_path, max_bytes=100)
    assert list(tmp_path.iterdir()) == []
