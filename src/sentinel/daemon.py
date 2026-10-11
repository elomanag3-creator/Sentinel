"""`sentinel daemon`: one process, one loop - periodic audits plus periodic log anomaly detection."""
import logging
import os
import signal
import threading
import time

from .audit.runner import run_audit
from .db import Database

log = logging.getLogger("sentinel.daemon")


class DetectJob:
    """Loads (or auto-trains) the model, reloads it when the file changes, reports only *new* anomalies."""

    def __init__(self, settings, db):
        self.s, self.db, self.det, self.mtime, self.seen = settings, db, None, None, set()

    def _model(self):
        from .detect import runner
        from .detect.model import Detector
        if not os.path.exists(self.s.model):
            log.warning("no model at %s - training from %s", self.s.model, ", ".join(self.s.files))
            try:
                log.info("trained: %s", runner.train(self.s, self.db))
            except (ValueError, OSError) as exc:
                log.warning("cannot train yet (%s); will retry next cycle", exc)
                return None
        mtime = os.path.getmtime(self.s.model)
        if self.det is None or mtime != self.mtime:
            self.det, self.mtime = Detector.load(self.s.model), mtime
            log.info("model loaded (%s mode)", self.det.mode)
        return self.det

    def __call__(self):
        from .detect import runner
        det = self._model()
        if det is None:
            return
        run_id, anomalies, nwin, nev = runner.detect(self.s, self.db, det, lookback_hours=self.s.lookback_hours,
                                                     novelty=self.s.novelty, seen=self.seen)
        for a in anomalies:
            log.warning("ANOMALY [%s] %s @ %s: %s", a.severity.upper(), a.title, f"{a.start:%Y-%m-%d %H:%M}", a.detail[:200])


def audit_job(settings, db):
    run_id = run_audit(db, settings)
    run = db.get_run(run_id)
    log.info("audit run #%d finished: %d findings, worst=%s", run_id, run["total"], run["max_severity"])


def run_daemon(settings, once: bool = False) -> None:
    db = Database(settings.db)
    stop = threading.Event()
    if threading.current_thread() is threading.main_thread():
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda *_: stop.set())
    jobs = [("audit", settings.audit_interval, lambda: audit_job(settings, db))]
    if settings.files:
        jobs.append(("detect", settings.detect_interval, DetectJob(settings, db)))
    else:
        log.info("no [detect] files configured - running audits only")
    log.info("daemon started: %s", ", ".join(f"{n} every {i}s" for n, i, _ in jobs))
    due = {name: 0.0 for name, _, _ in jobs}
    try:
        while not stop.is_set():
            for name, interval, fn in jobs:
                if time.monotonic() >= due[name]:
                    try:
                        fn()
                    except Exception:
                        log.exception("%s job failed (will retry next cycle)", name)
                    due[name] = time.monotonic() + interval
            if once:
                break
            stop.wait(max(1.0, min(due.values()) - time.monotonic()))
    finally:
        db.close()
        log.info("daemon stopped")
