import logging
import socket

from ..db import RUN_LOCK, Database, capture_logs
from ..models import Finding
from ..registry import load_checks

log = logging.getLogger("sentinel.audit")


def hostname(host_root: str) -> str:
    try:
        with open(f"{host_root.rstrip('/')}/etc/hostname") as fh:
            return fh.read().strip() or socket.gethostname()
    except OSError:
        return socket.gethostname()


def run_audit(db: Database, settings, checks=None) -> int:
    available = load_checks()
    checks = checks or settings.checks
    unknown = [c for c in checks if c not in available]
    if unknown:
        raise ValueError(f"unknown check(s): {', '.join(unknown)} (available: {', '.join(sorted(available))})")
    cfg = settings.audit_config()
    with RUN_LOCK:
        return _run(db, cfg, available, checks)


def _run(db, cfg, available, checks) -> int:
    run_id = db.start_run("audit", hostname(cfg.host_root), cfg.host_root, checks)
    with capture_logs(db, run_id):
        log.info("audit started (checks=%s, host_root=%s)", ",".join(checks), cfg.host_root)
        for name in checks:
            try:
                findings = available[name](cfg)
            except Exception as exc:          # one broken check must not kill the run
                log.exception("check %s crashed", name)
                findings = [Finding(name, "info", f"Check '{name}' failed", repr(exc))]
            for f in findings:
                db.add_finding(run_id, f)
            log.info("check %s done: %d findings", name, len(findings))
        log.info("audit finished")
    db.finish_run(run_id)
    return run_id
