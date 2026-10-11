"""One SQLite database for everything: audit runs, detection runs, findings (audit + anomaly) and logs."""
import logging
import os
from contextlib import contextmanager
import sqlite3
from datetime import datetime, timedelta, timezone

from .models import Finding, sev_rank

MIGRATIONS = [  # append new migrations; never edit old ones. Version is stored in PRAGMA user_version.
    """
    CREATE TABLE runs (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        kind         TEXT NOT NULL CHECK (kind IN ('audit','detect')),
        started_at   TEXT NOT NULL,
        finished_at  TEXT,
        hostname     TEXT,
        host_root    TEXT,
        checks       TEXT,
        total        INTEGER NOT NULL DEFAULT 0,
        max_severity TEXT
    );
    CREATE TABLE findings (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id       INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
        source       TEXT NOT NULL CHECK (source IN ('audit','anomaly')),
        check_name   TEXT NOT NULL,
        severity     TEXT NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
        title        TEXT NOT NULL,
        detail       TEXT,
        target       TEXT,
        window_start TEXT,
        window_end   TEXT,
        score        REAL,
        created_at   TEXT NOT NULL
    );
    CREATE TABLE logs (
        id      INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id  INTEGER REFERENCES runs(id) ON DELETE CASCADE,
        ts      TEXT NOT NULL,
        level   TEXT NOT NULL,
        logger  TEXT,
        message TEXT NOT NULL
    );
    CREATE INDEX idx_findings_run  ON findings(run_id, severity);
    CREATE INDEX idx_findings_time ON findings(created_at);
    CREATE INDEX idx_logs_run      ON logs(run_id);
    """,
]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def migrate(conn: sqlite3.Connection, migrations=None) -> int:
    migrations = MIGRATIONS if migrations is None else migrations
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version > len(migrations):
        raise RuntimeError(f"database schema v{version} is newer than this sentinel (v{len(migrations)})")
    for i, sql in enumerate(migrations[version:], start=version + 1):
        conn.executescript(sql)
        conn.execute(f"PRAGMA user_version = {i}")
    conn.commit()
    return len(migrations)


class Database:
    def __init__(self, path: str, migrations=None):
        if path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.conn = sqlite3.connect(path, timeout=30)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        if path != ":memory:":
            self.conn.execute("PRAGMA journal_mode = WAL")   # readers (API/dashboard later) don't block the writer
        migrate(self.conn, migrations)

    # -- writing ----------------------------------------------------------------------------
    def start_run(self, kind: str, hostname: str, host_root: str, checks) -> int:
        cur = self.conn.execute("INSERT INTO runs (kind, started_at, hostname, host_root, checks) VALUES (?,?,?,?,?)",
                                (kind, now_iso(), hostname, host_root, ",".join(checks)))
        self.conn.commit()
        return cur.lastrowid

    def add_finding(self, run_id: int, f: Finding) -> None:
        self.conn.execute(
            "INSERT INTO findings (run_id, source, check_name, severity, title, detail, target,"
            " window_start, window_end, score, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (run_id, f.source, f.check, f.severity, f.title, f.detail, f.target,
             f.window_start, f.window_end, f.score, now_iso()))
        self.conn.commit()

    def log(self, run_id, level: str, logger: str, message: str) -> None:
        self.conn.execute("INSERT INTO logs (run_id, ts, level, logger, message) VALUES (?,?,?,?,?)",
                          (run_id, now_iso(), level, logger, message))
        self.conn.commit()

    def finish_run(self, run_id: int) -> None:
        rows = self.conn.execute("SELECT severity FROM findings WHERE run_id=?", (run_id,)).fetchall()
        worst = max((r["severity"] for r in rows), key=sev_rank, default=None)
        self.conn.execute("UPDATE runs SET finished_at=?, total=?, max_severity=? WHERE id=?",
                          (now_iso(), len(rows), worst, run_id))
        self.conn.commit()

    # -- reading ----------------------------------------------------------------------------
    def list_runs(self, limit=10, kind=None):
        q, args = "SELECT * FROM runs", []
        if kind:
            q, args = q + " WHERE kind=?", [kind]
        return self.conn.execute(q + " ORDER BY id DESC LIMIT ?", args + [limit]).fetchall()

    def get_run(self, run_id: int):
        return self.conn.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()

    def get_findings(self, run_id: int):
        rows = self.conn.execute("SELECT * FROM findings WHERE run_id=?", (run_id,)).fetchall()
        return sorted(rows, key=lambda r: (-sev_rank(r["severity"]), r["check_name"], r["title"]))

    def get_logs(self, run_id: int):
        return self.conn.execute("SELECT * FROM logs WHERE run_id=? ORDER BY id", (run_id,)).fetchall()

    def diff(self, old_id: int, new_id: int):
        q = """SELECT n.* FROM findings n WHERE n.run_id=:a AND NOT EXISTS (
                 SELECT 1 FROM findings o WHERE o.run_id=:b AND o.source=n.source AND o.check_name=n.check_name
                 AND o.title=n.title AND IFNULL(o.target,'')=IFNULL(n.target,''))"""
        return (self.conn.execute(q, {"a": new_id, "b": old_id}).fetchall(),
                self.conn.execute(q, {"a": old_id, "b": new_id}).fetchall())

    def timeline(self, hours: float = 24, min_severity: str = "low", limit: int = 200):
        """Audit findings and anomalies on one time axis (anomalies use their window start)."""
        since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat(timespec="seconds")
        ok = [s for s in ("info", "low", "medium", "high", "critical") if sev_rank(s) >= sev_rank(min_severity)]
        marks = ",".join("?" * len(ok))
        return self.conn.execute(
            f"SELECT f.*, COALESCE(f.window_start, f.created_at) AS ts, r.hostname FROM findings f "
            f"JOIN runs r ON r.id=f.run_id WHERE COALESCE(f.window_start, f.created_at) >= ? "
            f"AND f.severity IN ({marks}) ORDER BY ts DESC, f.id DESC LIMIT ?", [since, *ok, limit]).fetchall()

    def close(self):
        self.conn.close()


class SqlLogHandler(logging.Handler):
    """Stores every log record emitted during a run in the `logs` table."""

    def __init__(self, db: Database, run_id: int):
        super().__init__()
        self.db, self.run_id = db, run_id

    def emit(self, record):
        try:
            self.db.log(self.run_id, record.levelname, record.name, record.getMessage())
        except Exception:
            self.handleError(record)


@contextmanager
def capture_logs(db: Database, run_id: int):
    """Everything logged under the `sentinel.*` loggers while inside the block is stored with this run."""
    logger = logging.getLogger("sentinel")
    handler, old = SqlLogHandler(db, run_id), logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        yield
    finally:
        logger.removeHandler(handler)
        logger.setLevel(old)
