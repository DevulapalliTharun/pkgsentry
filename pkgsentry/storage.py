"""Scan history in SQLite, so packages scanned on different days can be linked. Every query uses parameters:
package names, file paths and indicators are attacker-controlled text."""

import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from pkgsentry.campaigns import Indicator

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY,
    package TEXT NOT NULL,
    version TEXT NOT NULL,
    kind TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    score INTEGER NOT NULL,
    level TEXT NOT NULL,
    scanned_at TEXT NOT NULL,
    UNIQUE (package, version, kind)
);
CREATE TABLE IF NOT EXISTS indicators (
    scan_id INTEGER NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    key TEXT NOT NULL,
    path TEXT NOT NULL,
    line INTEGER NOT NULL,
    hidden INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS indicators_by_key ON indicators (key);
"""


@dataclass(frozen=True)
class StoredScan:
    package: str
    version: str
    kind: str
    score: int
    level: str
    indicators: tuple[Indicator, ...]


def save_scan(db: Path, package: str, version: str, kind: str, sha256: str, score: int, level: str,
              indicators: list[Indicator]) -> None:
    """Store one scan; scanning the same file again replaces the earlier result."""
    with closing(_connect(db)) as connection, connection:
        connection.execute("DELETE FROM scans WHERE package = ? AND version = ? AND kind = ?", (package, version, kind))
        scan_id = connection.execute(
            "INSERT INTO scans (package, version, kind, sha256, score, level, scanned_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (package, version, kind, sha256, score, level, datetime.now(timezone.utc).isoformat(timespec="seconds")),
        ).lastrowid
        connection.executemany(
            "INSERT INTO indicators (scan_id, kind, value, key, path, line, hidden) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [(scan_id, i.kind, i.value, i.key, i.path, i.line, i.hidden) for i in indicators],
        )


def load_scans(db: Path) -> list[StoredScan]:
    with closing(_connect(db)) as connection:
        rows = connection.execute("SELECT id, package, version, kind, score, level FROM scans "
                                  "ORDER BY package, version, kind").fetchall()
        found: dict[int, list[Indicator]] = {}
        for scan_id, *fields in connection.execute(
                "SELECT scan_id, kind, value, key, path, line, hidden FROM indicators ORDER BY rowid"):
            kind, value, key, path, line, hidden = fields
            found.setdefault(scan_id, []).append(Indicator(kind, value, key, path, line, bool(hidden)))
    return [StoredScan(package, version, kind, score, level, tuple(found.get(scan_id, ())))
            for scan_id, package, version, kind, score, level in rows]


def _connect(db: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(db)
    connection.execute("PRAGMA foreign_keys = ON")
    connection.executescript(_SCHEMA)
    return connection
