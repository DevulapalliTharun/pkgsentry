"""Scan history in SQLite, so packages scanned on different days can be linked. Every query uses parameters:
package names, file paths and indicators are attacker-controlled text."""

import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from pkgsentry.campaigns import Indicator
from pkgsentry.scoring import RiskSignal
from pkgsentry.triage.evidence import Excerpt

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
CREATE INDEX IF NOT EXISTS indicators_by_scan ON indicators (scan_id);
CREATE TABLE IF NOT EXISTS signals (
    scan_id INTEGER NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    category TEXT NOT NULL,
    points INTEGER NOT NULL,
    strength TEXT NOT NULL,
    context TEXT NOT NULL,
    detail TEXT NOT NULL,
    path TEXT NOT NULL,
    line INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS signals_by_scan ON signals (scan_id);
CREATE TABLE IF NOT EXISTS excerpts (
    scan_id INTEGER NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    tag TEXT NOT NULL,
    path TEXT NOT NULL,
    flagged TEXT NOT NULL,
    rules TEXT NOT NULL,
    header TEXT NOT NULL,
    body TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS excerpts_by_scan ON excerpts (scan_id);
"""


@dataclass(frozen=True)
class StoredExcerpt:
    tag: str
    path: str
    flagged: tuple[int, ...]
    rules: str
    header: str
    body: tuple[str, ...]  # already escaped and size-limited by the evidence pack


@dataclass(frozen=True)
class StoredScan:
    package: str
    version: str
    kind: str
    score: int
    level: str
    indicators: tuple[Indicator, ...]
    sha256: str = ""
    scanned_at: str = ""
    signals: tuple[RiskSignal, ...] = ()  # only filled in by load_package
    excerpts: tuple[StoredExcerpt, ...] = ()  # only filled in by load_package


def ensure_schema(db: Path) -> None:
    """Create any missing tables, so a history file from an earlier step keeps working."""
    with closing(_connect(db, create=True)):
        pass


def save_scan(db: Path, package: str, version: str, kind: str, sha256: str, score: int, level: str,
              indicators: list[Indicator], signals: tuple[RiskSignal, ...] = (),
              excerpts: list[Excerpt] | tuple[Excerpt, ...] = ()) -> None:
    """Store one scan; scanning the same file again replaces the earlier result."""
    with closing(_connect(db, create=True)) as connection, connection:
        connection.execute("DELETE FROM scans WHERE package = ? AND version = ? AND kind = ?", (package, version, kind))
        scan_id = connection.execute(
            "INSERT INTO scans (package, version, kind, sha256, score, level, scanned_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (package, version, kind, sha256, score, level, datetime.now(timezone.utc).isoformat(timespec="seconds")),
        ).lastrowid
        connection.executemany(
            "INSERT INTO indicators (scan_id, kind, value, key, path, line, hidden) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [(scan_id, i.kind, i.value, i.key, i.path, i.line, i.hidden) for i in indicators],
        )
        connection.executemany(
            "INSERT INTO signals (scan_id, category, points, strength, context, detail, path, line) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [(scan_id, s.category, s.points, s.strength, s.context, s.detail, s.path, s.line) for s in signals],
        )
        connection.executemany(
            "INSERT INTO excerpts (scan_id, tag, path, flagged, rules, header, body) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [(scan_id, e.tag, e.path, ",".join(map(str, e.flagged)), ", ".join(e.rules), e.header(),
              "\n".join(e.body())) for e in excerpts],
        )


def load_scans(db: Path, signals: bool = False) -> list[StoredScan]:
    """Every saved scan with its indicators; signals=True adds the score breakdown, never the code excerpts."""
    with closing(_connect(db)) as connection:
        rows = connection.execute("SELECT id, package, version, kind, score, level, sha256, scanned_at FROM scans "
                                  "ORDER BY package, version, kind").fetchall()
        found = _indicators(connection)
        scored: dict[int, list[RiskSignal]] = {}
        if signals:
            for scan_id, *fields in connection.execute(
                    "SELECT scan_id, category, points, strength, context, detail, path, line FROM signals "
                    "ORDER BY points DESC, category"):
                scored.setdefault(scan_id, []).append(RiskSignal(*fields))
    return [StoredScan(package, version, kind, score, level, tuple(found.get(scan_id, ())), sha256, scanned_at,
                       tuple(scored.get(scan_id, ())))
            for scan_id, package, version, kind, score, level, sha256, scanned_at in rows]


def load_package(db: Path, package: str) -> list[StoredScan]:
    """Every saved scan of one package, newest first, with its score breakdown and code excerpts."""
    with closing(_connect(db)) as connection:
        rows = connection.execute(
            "SELECT id, version, kind, score, level, sha256, scanned_at FROM scans WHERE package = ?", (package,)
        ).fetchall()
        found = _indicators(connection, [row[0] for row in rows])
        scans = []
        for scan_id, version, kind, score, level, sha256, scanned_at in rows:
            signals = connection.execute(
                "SELECT category, points, strength, context, detail, path, line FROM signals WHERE scan_id = ? "
                "ORDER BY points DESC, category", (scan_id,)).fetchall()
            excerpts = connection.execute(
                "SELECT tag, path, flagged, rules, header, body FROM excerpts WHERE scan_id = ? ORDER BY rowid",
                (scan_id,)).fetchall()
            scans.append(StoredScan(
                package, version, kind, score, level, tuple(found.get(scan_id, ())), sha256, scanned_at,
                tuple(RiskSignal(*row) for row in signals),
                tuple(StoredExcerpt(tag, path, tuple(int(n) for n in flagged.split(",") if n), rules, header,
                                    tuple(body.split("\n"))) for tag, path, flagged, rules, header, body in excerpts)))
    return sorted(scans, key=lambda s: (s.scanned_at, s.version, s.kind), reverse=True)


def _indicators(connection: sqlite3.Connection, only: list[int] | None = None) -> dict[int, list[Indicator]]:
    found: dict[int, list[Indicator]] = {}
    for scan_id, kind, value, key, path, line, hidden in connection.execute(
            "SELECT scan_id, kind, value, key, path, line, hidden FROM indicators ORDER BY rowid"):
        if only is None or scan_id in only:
            found.setdefault(scan_id, []).append(Indicator(kind, value, key, path, line, bool(hidden)))
    return found


def _connect(db: Path, create: bool = False) -> sqlite3.Connection:
    """Reading opens the file read-only, so a bug in a viewer can never change the history."""
    if create:
        connection = sqlite3.connect(db)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.executescript(_SCHEMA)
        return connection
    connection = sqlite3.connect(f"{db.resolve().as_uri()}?mode=ro", uri=True)
    connection.execute("PRAGMA query_only = ON")
    return connection
