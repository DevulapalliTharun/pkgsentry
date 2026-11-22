import io
import stat
import tarfile
import uuid
import zipfile
from pathlib import Path

import pytest

from pkgsentry.fetch.extract import ExtractionError, Limits, safe_extract


def make_tar(path: Path, files: dict[str, bytes], links: dict[str, tuple[bytes, str]] | None = None) -> Path:
    with tarfile.open(path, "w:gz") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        for name, (kind, target) in (links or {}).items():
            info = tarfile.TarInfo(name)
            info.type = kind
            info.linkname = target
            tar.addfile(info)
    return path


def make_zip(path: Path, files: dict[str, bytes], symlinks: dict[str, str] | None = None) -> Path:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
        for name, target in (symlinks or {}).items():
            info = zipfile.ZipInfo(name)
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, target)
    return path


def reasons(report) -> dict[str, str]:
    return dict(report.skipped)


def test_extracts_a_normal_sdist(tmp_path):
    archive = make_tar(tmp_path / "demo-1.0.tar.gz", {
        "demo-1.0/setup.py": b"from setuptools import setup\nsetup(name='demo')\n",
        "demo-1.0/demo/__init__.py": b"",
    })
    report = safe_extract(archive, tmp_path / "out")
    assert sorted(report.files) == ["demo-1.0/demo/__init__.py", "demo-1.0/setup.py"]
    assert (tmp_path / "out/demo-1.0/setup.py").read_bytes().startswith(b"from setuptools")
    assert report.skipped == []


def test_extracted_files_are_not_executable(tmp_path):
    archive = make_tar(tmp_path / "a.tar.gz", {"run.sh": b"echo hi"})
    safe_extract(archive, tmp_path / "out")
    assert not (tmp_path / "out/run.sh").stat().st_mode & stat.S_IXUSR


def test_blocks_path_traversal_and_absolute_paths_in_tar(tmp_path):
    outside = Path("/tmp") / f"pkgsentry-test-{uuid.uuid4().hex}.txt"
    archive = make_tar(tmp_path / "evil.tar.gz", {
        "../escaped.txt": b"x",
        "pkg/../../escaped2.txt": b"x",
        str(outside): b"x",
        "..\\windows.txt": b"x",
        "pkg/ok.txt": b"fine",
    })
    report = safe_extract(archive, tmp_path / "out")
    assert report.files == ["pkg/ok.txt"]
    assert reasons(report)["../escaped.txt"] == "path traversal (..)"
    assert reasons(report)[str(outside)] == "absolute path"
    assert reasons(report)["..\\windows.txt"] == "path traversal (..)"
    assert not (tmp_path / "escaped.txt").exists()
    assert not outside.exists()


def test_skips_links_in_tar(tmp_path):
    archive = make_tar(
        tmp_path / "links.tar.gz",
        {"pkg/docs/passwd": b"harmless"},
        links={"pkg/docs": (tarfile.SYMTYPE, "/etc"), "pkg/hard": (tarfile.LNKTYPE, "/etc/passwd")},
    )
    report = safe_extract(archive, tmp_path / "out")
    assert reasons(report) == {"pkg/docs": "symlink", "pkg/hard": "hard link"}
    docs = tmp_path / "out/pkg/docs"
    assert docs.is_dir() and not docs.is_symlink()


def test_blocks_traversal_and_symlinks_in_zip(tmp_path):
    archive = make_zip(tmp_path / "evil.whl", {"../../escaped.txt": b"x", "pkg/ok.py": b""}, {"pkg/link": "/etc"})
    report = safe_extract(archive, tmp_path / "out")
    assert report.files == ["pkg/ok.py"]
    assert reasons(report) == {"../../escaped.txt": "path traversal (..)", "pkg/link": "symlink"}


def test_records_duplicate_entries(tmp_path):
    path = tmp_path / "dup.tar.gz"
    with tarfile.open(path, "w:gz") as tar:
        for data in (b"first", b"second"):
            info = tarfile.TarInfo("setup.py")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    report = safe_extract(path, tmp_path / "out")
    assert reasons(report) == {"setup.py": "duplicate entry (later copy kept)"}
    assert (tmp_path / "out/setup.py").read_bytes() == b"second"


def test_stops_a_decompression_bomb_by_total_size(tmp_path):
    archive = make_zip(tmp_path / "bomb.zip", {"zeros.bin": b"\0" * (3 * 1024 * 1024)})
    with pytest.raises(ExtractionError, match="decompression bomb"):
        safe_extract(archive, tmp_path / "out", Limits(max_total_bytes=1024 * 1024))
    assert not (tmp_path / "out").exists()


def test_stops_a_decompression_bomb_by_ratio(tmp_path):
    archive = make_zip(tmp_path / "bomb.zip", {"zeros.bin": b"\0" * (3 * 1024 * 1024)})
    assert archive.stat().st_size < 30 * 1024
    with pytest.raises(ExtractionError, match="expands more than 100x"):
        safe_extract(archive, tmp_path / "out", Limits(ratio_floor_bytes=1024 * 1024))


def test_stops_too_many_files(tmp_path):
    archive = make_tar(tmp_path / "many.tar.gz", {f"f{i}.txt": b"x" for i in range(5)})
    with pytest.raises(ExtractionError, match="more than 3 files"):
        safe_extract(archive, tmp_path / "out", Limits(max_files=3))


def test_rejects_unknown_and_corrupt_archives(tmp_path):
    with pytest.raises(ExtractionError, match="unsupported"):
        safe_extract(tmp_path / "x.rar", tmp_path / "out")
    corrupt = tmp_path / "broken.tar.gz"
    corrupt.write_bytes(b"not really an archive")
    with pytest.raises(ExtractionError, match="cannot read archive"):
        safe_extract(corrupt, tmp_path / "out")
