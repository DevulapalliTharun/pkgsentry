"""Download a package file from PyPI's file host and verify its SHA-256. Nothing is installed or run."""

import hashlib
import re
from pathlib import Path
from urllib.parse import urlparse

import requests

from pkgsentry.fetch.pypi import TIMEOUT_SECONDS, USER_AGENT, PyPIError
from pkgsentry.models import ReleaseFile

ALLOWED_HOSTS = {"files.pythonhosted.org"}
MAX_DOWNLOAD_BYTES = 100 * 1024 * 1024
CHUNK_BYTES = 64 * 1024
_FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")


class IntegrityError(PyPIError):
    """The downloaded bytes do not match the SHA-256 that PyPI published."""


def download_file(file: ReleaseFile, dest_dir: Path, max_bytes: int = MAX_DOWNLOAD_BYTES) -> Path:
    _check_source(file)
    dest_dir.mkdir(parents=True, exist_ok=True)
    target = dest_dir / file.filename
    partial = target.with_name(target.name + ".part")
    try:
        actual = _stream(file.url, partial, max_bytes)
        if actual != file.sha256.lower():
            raise IntegrityError(
                f"SHA-256 mismatch for {file.filename}: PyPI says {file.sha256[:12]}..., got {actual[:12]}..."
            )
    except BaseException:
        partial.unlink(missing_ok=True)
        raise
    partial.replace(target)
    return target


def _check_source(file: ReleaseFile) -> None:
    url = urlparse(file.url)
    if url.scheme != "https" or url.hostname not in ALLOWED_HOSTS:
        raise PyPIError(f"refusing to download from an untrusted location: {file.url}")
    if not _FILENAME_RE.match(file.filename):
        raise PyPIError(f"refusing an unsafe file name: {file.filename!r}")
    if not file.sha256:
        raise IntegrityError(f"PyPI published no SHA-256 for {file.filename}")


def _stream(url: str, path: Path, max_bytes: int) -> str:
    digest = hashlib.sha256()
    received = 0
    try:
        # No redirects: a redirect could lead to a host outside the allow-list.
        with requests.get(
            url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT_SECONDS, stream=True, allow_redirects=False
        ) as response, path.open("wb") as out:
            if response.status_code != 200:
                raise PyPIError(f"download failed with HTTP {response.status_code}")
            for chunk in response.iter_content(CHUNK_BYTES):
                received += len(chunk)
                if received > max_bytes:
                    raise PyPIError(f"file is larger than {max_bytes:,} bytes; refusing to download it")
                digest.update(chunk)
                out.write(chunk)
    except requests.RequestException as error:
        raise PyPIError(f"download failed: {error}") from error
    return digest.hexdigest()
