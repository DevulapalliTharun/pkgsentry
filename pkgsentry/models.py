"""Plain data shapes shared by every stage of the pipeline."""

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class ReleaseFile:
    filename: str
    packagetype: str  # PyPI's names: "sdist" or "bdist_wheel"
    url: str
    size: int
    sha256: str
    upload_time: datetime | None

    @property
    def kind(self) -> str:
        return {"sdist": "sdist", "bdist_wheel": "wheel"}.get(self.packagetype, self.packagetype)


@dataclass(frozen=True)
class PackageInfo:
    name: str
    version: str
    summary: str
    author: str
    author_email: str
    homepage: str
    description_length: int
    release_count: int
    first_upload: datetime | None
    files: tuple[ReleaseFile, ...]

    @property
    def uploaded(self) -> datetime | None:
        times = [f.upload_time for f in self.files if f.upload_time]
        return min(times) if times else None

    @property
    def has_wheel(self) -> bool:
        return any(f.kind == "wheel" for f in self.files)
