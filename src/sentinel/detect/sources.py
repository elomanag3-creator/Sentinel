"""Event sources: syslog-style text files, or sentinel's own audit history (one window per audit run)."""
from datetime import datetime
from typing import Iterable, Optional

from .parser import Event, parse_line

LEVEL_FOR_SEVERITY = {"critical": "CRITICAL", "high": "ERROR", "medium": "WARNING", "low": "INFO", "info": "INFO"}


def read_files(paths: Iterable[str], ref: Optional[datetime] = None, since: Optional[datetime] = None) -> list:
    ref, events = ref or datetime.now(), []
    for path in paths:
        with open(path, errors="replace") as fh:
            for line in fh:
                ev = parse_line(line, ref)
                if ev and (since is None or ev.ts >= since):
                    events.append(ev)
    events.sort(key=lambda e: e.ts)
    return events


def _local_naive(iso: str) -> datetime:
    """Convention used everywhere in detect/: naive datetime = local wall clock."""
    dt = datetime.fromisoformat(iso)
    return dt.astimezone().replace(tzinfo=None) if dt.tzinfo else dt


def read_audit_history(db) -> list:
    """Every audit run becomes one group: its log lines + its findings are the run's events."""
    events = []
    for r in db.conn.execute(
            "SELECT l.run_id, l.ts, l.level, l.logger, l.message, r.hostname FROM logs l "
            "JOIN runs r ON r.id = l.run_id WHERE r.kind = 'audit' ORDER BY l.id"):
        events.append(Event(_local_naive(r["ts"]), r["hostname"] or "", r["logger"] or "sentinel",
                            r["message"], r["level"], r["run_id"]).finalize())
    for r in db.conn.execute(
            "SELECT f.run_id, f.created_at, f.severity, f.check_name, f.title, r.hostname FROM findings f "
            "JOIN runs r ON r.id = f.run_id WHERE r.kind = 'audit' ORDER BY f.id"):
        events.append(Event(_local_naive(r["created_at"]), r["hostname"] or "", "sentinel.finding",
                            f"{r['severity']} {r['check_name']} {r['title']}",
                            LEVEL_FOR_SEVERITY[r["severity"]], r["run_id"]).finalize(mask_numbers=False))
    events.sort(key=lambda e: e.ts)
    return events
