"""Unpack an untrusted archive safely: block path tricks, links and decompression bombs."""

import re
import shutil
import stat
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import BinaryIO

CHUNK_BYTES = 64 * 1024
ZIP_SUFFIXES = (".whl", ".zip", ".egg")
TAR_SUFFIXES = (".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar")


@dataclass(frozen=True)
class Limits:
    max_files: int = 20_000
    max_file_bytes: int = 50 * 1024 * 1024
    max_total_bytes: int = 200 * 1024 * 1024
    max_ratio: int = 100  # extracted bytes allowed per archive byte
    ratio_floor_bytes: int = 10 * 1024 * 1024  # small archives can legitimately compress very well


@dataclass
class ExtractionReport:
    root: Path
    files: list[str] = field(default_factory=list)
    bytes_written: int = 0
    skipped: list[tuple[str, str]] = field(default_factory=list)  # (entry name, reason)


class ExtractionError(Exception):
    """Extraction stopped: the archive is unreadable or looks like a decompression bomb."""


def safe_extract(archive: Path, dest: Path, limits: Limits = Limits()) -> ExtractionReport:
    if archive.name.endswith(ZIP_SUFFIXES):
        extract_entries = _extract_zip
    elif archive.name.endswith(TAR_SUFFIXES):
        extract_entries = _extract_tar
    else:
        raise ExtractionError(f"unsupported archive type: {archive.name}")
    dest.mkdir(parents=True, exist_ok=True)
    report = ExtractionReport(root=dest.resolve())
    budget = _Budget(limits, archive.stat().st_size)
    try:
        extract_entries(archive, report, budget)
    except (tarfile.TarError, zipfile.BadZipFile, EOFError) as error:
        shutil.rmtree(dest, ignore_errors=True)
        raise ExtractionError(f"cannot read archive: {error}") from error
    except BaseException:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    return report


def _extract_tar(archive: Path, report: ExtractionReport, budget: "_Budget") -> None:
    with tarfile.open(archive, "r:*") as tar:
        for member in tar:
            if member.isdir():
                continue
            if not member.isfile():
                report.skipped.append((member.name, _special_kind(member)))
                continue
            target = _checked_target(member.name, report)
            if target:
                _write(tar.extractfile(member), target, member.name, report, budget)


def _extract_zip(archive: Path, report: ExtractionReport, budget: "_Budget") -> None:
    with zipfile.ZipFile(archive) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            if stat.S_ISLNK(info.external_attr >> 16):
                report.skipped.append((info.filename, "symlink"))
                continue
            target = _checked_target(info.filename, report)
            if target:
                with zf.open(info) as source:
                    _write(source, target, info.filename, report, budget)


def _special_kind(member: tarfile.TarInfo) -> str:
    if member.issym():
        return "symlink"
    if member.islnk():
        return "hard link"
    return "device or special file"


def _checked_target(name: str, report: ExtractionReport) -> Path | None:
    problem = _name_problem(name)
    if not problem:
        target = (report.root / name.replace("\\", "/")).resolve()
        if target == report.root or not target.is_relative_to(report.root):
            problem = "escapes the extraction folder"
    if problem:
        report.skipped.append((name, problem))
        return None
    return target


def _name_problem(name: str) -> str:
    if not name or "\x00" in name:
        return "empty name or NUL byte"
    normalized = name.replace("\\", "/")  # "..\\" is traversal on Windows
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        return "absolute path"
    if ".." in PurePosixPath(normalized).parts:
        return "path traversal (..)"
    return ""


class _Budget:
    def __init__(self, limits: Limits, archive_bytes: int):
        self.limits = limits
        self.archive_bytes = max(archive_bytes, 1)
        self.files = 0
        self.total = 0

    def add_file(self) -> None:
        self.files += 1
        if self.files > self.limits.max_files:
            raise ExtractionError(f"more than {self.limits.max_files:,} files: possible decompression bomb")

    def add_bytes(self, count: int, file_so_far: int, name: str) -> None:
        self.total += count
        limits = self.limits
        if file_so_far > limits.max_file_bytes:
            raise ExtractionError(f"{name} expands past {limits.max_file_bytes:,} bytes: possible decompression bomb")
        if self.total > limits.max_total_bytes:
            raise ExtractionError(f"archive expands past {limits.max_total_bytes:,} bytes: possible decompression bomb")
        if self.total > limits.ratio_floor_bytes and self.total > self.archive_bytes * limits.max_ratio:
            raise ExtractionError(
                f"archive expands more than {limits.max_ratio}x its size: possible decompression bomb"
            )


def _write(source: BinaryIO, target: Path, name: str, report: ExtractionReport, budget: _Budget) -> None:
    budget.add_file()
    relative = str(target.relative_to(report.root))
    if target.exists():
        report.skipped.append((name, "duplicate entry (later copy kept)"))
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        written = 0
        with target.open("wb") as out:
            while chunk := source.read(CHUNK_BYTES):
                written += len(chunk)
                budget.add_bytes(len(chunk), written, name)
                out.write(chunk)
    except OSError as error:
        report.skipped.append((name, f"cannot write: {error.strerror or error}"))
        return
    target.chmod(0o644)
    if relative not in report.files:
        report.files.append(relative)
    report.bytes_written += written
