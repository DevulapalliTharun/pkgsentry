"""Read package metadata from PyPI's JSON API. Nothing is downloaded or installed here."""

import re
from datetime import datetime

import requests

from pkgsentry.models import PackageInfo, ReleaseFile

PYPI_URL = "https://pypi.org/pypi"
USER_AGENT = "pkgsentry/0.1 (+https://github.com/DevulapalliTharun/pkgsentry)"
TIMEOUT_SECONDS = 15

# Only valid project names (PEP 508); anything else could change which URL we request.
_NAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+!_-]*$")


class PyPIError(Exception):
    """Any failure while talking to PyPI."""


class PackageNotFoundError(PyPIError):
    pass


def validate_name(name: str) -> str:
    if not _NAME_RE.match(name):
        raise ValueError(f"not a valid package name: {name!r}")
    return name


def validate_version(version: str) -> str:
    if not _VERSION_RE.match(version):
        raise ValueError(f"not a valid version: {version!r}")
    return version


def get_package_info(name: str, version: str | None = None) -> PackageInfo:
    validate_name(name)
    # The release history only exists in the project-wide response, not the per-version one.
    project = _get_json(f"{PYPI_URL}/{name}/json", what=name)
    if version is None:
        data = project
    else:
        validate_version(version)
        data = _get_json(f"{PYPI_URL}/{name}/{version}/json", what=f"{name} {version}")
    return parse_package(data, project.get("releases", {}))


def _get_json(url: str, what: str) -> dict:
    try:
        response = requests.get(
            url,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            timeout=TIMEOUT_SECONDS,
        )
    except requests.RequestException as error:
        raise PyPIError(f"could not reach PyPI: {error}") from error
    if response.status_code == 404:
        raise PackageNotFoundError(f"{what} is not on PyPI (it never existed, or PyPI removed it)")
    if not response.ok:
        raise PyPIError(f"PyPI returned HTTP {response.status_code} for {what}")
    return response.json()


def parse_package(data: dict, releases: dict) -> PackageInfo:
    info = data["info"]
    upload_times = [
        parsed
        for files in releases.values()
        for raw in files
        if (parsed := _parse_time(raw.get("upload_time_iso_8601")))
    ]
    return PackageInfo(
        name=info.get("name") or "",
        version=info.get("version") or "",
        summary=(info.get("summary") or "").strip(),
        author=(info.get("author") or "").strip(),
        author_email=(info.get("author_email") or "").strip(),
        homepage=_homepage(info),
        description_length=len(info.get("description") or ""),
        release_count=sum(1 for files in releases.values() if files),
        first_upload=min(upload_times) if upload_times else None,
        files=tuple(_parse_file(raw) for raw in data.get("urls", [])),
    )


def _parse_file(raw: dict) -> ReleaseFile:
    return ReleaseFile(
        filename=raw.get("filename", ""),
        packagetype=raw.get("packagetype", ""),
        url=raw.get("url", ""),
        size=int(raw.get("size") or 0),
        sha256=(raw.get("digests") or {}).get("sha256", ""),
        upload_time=_parse_time(raw.get("upload_time_iso_8601")),
    )


def _homepage(info: dict) -> str:
    if info.get("home_page"):
        return info["home_page"]
    urls = info.get("project_urls") or {}
    for key in ("Homepage", "homepage", "Home", "Source", "Repository"):
        if urls.get(key):
            return urls[key]
    return next(iter(urls.values()), "")


def _parse_time(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None
