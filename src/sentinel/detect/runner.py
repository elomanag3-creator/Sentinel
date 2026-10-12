"""Glue between detect/ and the database: train, detect, persist anomalies as findings."""
import logging
import os
from datetime import datetime, timedelta, timezone

from ..db import RUN_LOCK, Database, capture_logs
from ..models import Finding
from .features import EPOCH
from .model import Anomaly, Detector
from .sources import read_audit_history, read_files

log = logging.getLogger("sentinel.detect")


def _utc_iso(dt: datetime) -> str:
    """Detect-side datetimes are naive local wall-clock; the database stores UTC."""
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def load_events(settings, db: Database, files=None, audit_history=False, lookback_hours=None):
    """Returns (events, mode, description)."""
    if audit_history:
        return read_audit_history(db), "group", "audit history"
    files = files or settings.files
    if not files:
        raise ValueError("no log files given: use --file or set [detect] files in sentinel.toml")
    since = None
    if lookback_hours:
        raw = datetime.now() - timedelta(hours=lookback_hours)
        w = settings.window             # align to a window boundary so the first bucket is not partial
        since = EPOCH + timedelta(seconds=((raw - EPOCH).total_seconds() // w + 1) * w)
    return read_files(files, since=since), "time", ",".join(files)


def train(settings, db, files=None, audit_history=False, fill_gaps=True) -> dict:
    events, mode, desc = load_events(settings, db, files, audit_history)
    if not events:
        raise ValueError(f"no parsable events found in {desc}")
    det = Detector(mode, settings.window, settings.contamination)
    stats = det.fit(events, fill_gaps=fill_gaps and mode == "time")
    os.makedirs(os.path.dirname(os.path.abspath(settings.model)), exist_ok=True)
    det.save(settings.model)
    stats.update(mode=mode, source=desc, model=settings.model)
    return stats


def to_finding(a: Anomaly) -> Finding:
    return Finding(a.kind, a.severity, a.title, a.detail, a.host, source="anomaly",
                   window_start=_utc_iso(a.start), window_end=_utc_iso(a.end), score=a.score)


def detect(settings, db, det: Detector, files=None, audit_history=False, lookback_hours=None,
           novelty=True, seen=None) -> tuple:
    """Returns (run_id | None, anomalies, n_windows, n_events). With `seen` (daemon), only new anomalies count."""
    mode = "group" if audit_history else "time"
    if mode != det.mode:                      # check before reading (possibly huge) log files
        raise ValueError(f"model was trained in '{det.mode}' mode but this source is '{mode}'; "
                         "use a separate model file (--model) per source")
    events, _, desc = load_events(settings, db, files, audit_history, lookback_hours)
    anomalies, nwin = det.detect(events, novelty=novelty)
    if seen is not None:
        anomalies = [a for a in anomalies if (a.kind, a.start, a.detail) not in seen]
        seen.update((a.kind, a.start, a.detail) for a in anomalies)
        if not anomalies:
            return None, [], nwin, len(events)
    with RUN_LOCK:
        run_id = db.start_run("detect", events[0].host if events else "", desc, ["anomaly"])
        with capture_logs(db, run_id):
            log.info("analysed %d events in %d windows (%s)", len(events), nwin, desc)
            for a in anomalies:
                db.add_finding(run_id, to_finding(a))
            log.info("%d anomalies recorded", len(anomalies))
        db.finish_run(run_id)
    return run_id, anomalies, nwin, len(events)
