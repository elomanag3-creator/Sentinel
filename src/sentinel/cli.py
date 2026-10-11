import argparse
import json
import logging
import os
import sys
from collections import Counter

from . import __version__
from .config import ConfigError, describe, load_settings
from .db import Database
from .models import SEVERITIES, sev_rank

COLORS = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[90m"}


def _fmt(row, color=False) -> str:
    c, r = (COLORS[row["severity"]], "\033[0m") if color else ("", "")
    where = f" @ {row['window_start'][:16]}Z" if row["window_start"] else (f" [{row['target']}]" if row["target"] else "")
    line = f"{c}{row['severity'].upper():8}{r} {row['source'] + '/' + row['check_name']:24} {row['title']}{where}"
    return line + (f"\n{'':34}{row['detail']}" if row["detail"] else "")


def _print_run(db, run_id, fmt="text", logs=False):
    run, findings = db.get_run(run_id), db.get_findings(run_id)
    if fmt == "json":
        data = {"run": dict(run), "findings": [dict(f) for f in findings]}
        if logs:
            data["logs"] = [dict(x) for x in db.get_logs(run_id)]
        print(json.dumps(data, indent=2))
        return
    print(f"\n== Run #{run['id']} ({run['kind']}) on {run['hostname']} at {run['started_at']} ==")
    for f in findings:
        print(_fmt(f, sys.stdout.isatty()))
    counts = Counter(f["severity"] for f in findings)
    print("\nSummary: " + (", ".join(f"{counts[s]} {s}" for s in reversed(SEVERITIES) if counts[s]) or "no findings"))
    if logs:
        print("\n-- logs --")
        for x in db.get_logs(run_id):
            print(f"{x['ts']} {x['level']:7} {x['message']}")


def _exit_code(db, run_id, fail_on) -> int:
    worst = db.get_run(run_id)["max_severity"]
    return 2 if fail_on and worst and sev_rank(worst) >= sev_rank(fail_on) else 0


def _ml():
    try:
        from .detect import runner
        return runner
    except ImportError as exc:
        raise SystemExit(f"this command needs the ML extras: pip install 'sentinel-monitor[ml]'  ({exc})")


# ---- commands --------------------------------------------------------------------------------
def cmd_audit(a, s, db):
    from .audit.runner import run_audit
    if a.host_root:
        s.host_root = a.host_root
    if a.allow_ports is not None:
        s.allow_ports = [int(x) for x in a.allow_ports.split(",") if x.strip()]
    s.refresh_index = s.refresh_index or a.refresh_index
    checks = [c.strip() for c in a.checks.split(",") if c.strip()] if a.checks else None
    run_id = run_audit(db, s, checks)
    _print_run(db, run_id, a.format)
    return _exit_code(db, run_id, a.fail_on)


def cmd_train(a, s, db):
    runner = _ml()
    s.window, s.contamination = a.window or s.window, a.contamination or s.contamination
    if a.model:
        s.model = a.model
    stats = runner.train(s, db, a.file, a.audit_history, fill_gaps=not a.no_fill_gaps)
    print(f"model saved to {s.model}: {stats}")


def cmd_detect(a, s, db):
    runner = _ml()
    from .detect.model import Detector
    if a.model:
        s.model = a.model
    if a.window:
        s.window = a.window
    if not os.path.exists(s.model):
        raise ValueError(f"no model at {s.model} - run `sentinel train` first")
    det = Detector.load(s.model)
    run_id, anomalies, nwin, nev = runner.detect(s, db, det, a.file, a.audit_history,
                                                 a.lookback, novelty=not a.no_novelty and s.novelty)
    print(f"\nAnalysed {nev} events in {nwin} windows -> {len(anomalies)} anomalies", file=sys.stderr)
    _print_run(db, run_id, a.format)
    return _exit_code(db, run_id, a.fail_on)


def cmd_daemon(a, s, db):
    from .daemon import run_daemon
    db.close()
    run_daemon(s, once=a.once)


def cmd_history(a, s, db):
    for r in db.list_runs(a.limit, a.kind):
        print(f"#{r['id']:<4} {r['kind']:7} {r['started_at']}  {(r['hostname'] or ''):18} findings={r['total']:<4} worst={r['max_severity']}")


def cmd_show(a, s, db):
    if not db.get_run(a.run_id):
        raise ValueError(f"no run #{a.run_id}")
    _print_run(db, a.run_id, a.format, a.logs)


def cmd_diff(a, s, db):
    new, resolved = db.diff(a.old, a.new)
    print(f"== NEW in #{a.new} ({len(new)}) ==")
    print("\n".join(_fmt(f) for f in new))
    print(f"\n== RESOLVED since #{a.old} ({len(resolved)}) ==")
    print("\n".join(_fmt(f) for f in resolved))


def cmd_timeline(a, s, db):
    rows = db.timeline(a.hours, a.min_severity, a.limit)
    print(f"Timeline, last {a.hours:g}h, severity >= {a.min_severity} (times in UTC), {len(rows)} entries")
    for r in rows:
        print(f"{r['ts'][:16].replace('T', ' ')}  {_fmt(r, sys.stdout.isatty())}")


def cmd_demo(a, s, db):
    from .detect.demo import write_demo
    n, atk = write_demo(a.out_dir)
    print(f"wrote {n}\nwrote {atk}\n\nTry:\n  sentinel train --file {n}\n  sentinel detect --file {atk} --lookback 30\n  sentinel timeline")


def build_parser():
    p = argparse.ArgumentParser(prog="sentinel", description="Host security monitor: audits + log anomaly detection")
    p.add_argument("--version", action="version", version=f"sentinel {__version__}")
    p.add_argument("--config", help="TOML config (default: $SENTINEL_CONFIG, ./sentinel.toml, /etc/sentinel/sentinel.toml)")
    p.add_argument("--db", help="SQLite database (overrides config / $SENTINEL_DB)")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("audit", help="run a posture audit now")
    a.add_argument("--checks", help="comma list (default from config)")
    a.add_argument("--host-root")
    a.add_argument("--allow-ports", help="e.g. 22,443")
    a.add_argument("--refresh-index", action="store_true")
    a.add_argument("--fail-on", choices=SEVERITIES)
    a.add_argument("--format", choices=["text", "json"], default="text")

    def ml_source(sp):
        sp.add_argument("--file", action="append", help="log file (repeatable; default from config)")
        sp.add_argument("--audit-history", action="store_true", help="use past audit runs instead of log files")
        sp.add_argument("--model", help="model file (default from config)")
        sp.add_argument("--window", type=int, help="window seconds")

    t = sub.add_parser("train", help="learn what normal looks like")
    ml_source(t)
    t.add_argument("--contamination", type=float)
    t.add_argument("--no-fill-gaps", action="store_true")
    d = sub.add_parser("detect", help="find anomalies now")
    ml_source(d)
    d.add_argument("--lookback", type=float, help="only the last N hours")
    d.add_argument("--no-novelty", action="store_true")
    d.add_argument("--fail-on", choices=SEVERITIES)
    d.add_argument("--format", choices=["text", "json"], default="text")

    dm = sub.add_parser("daemon", help="run audits + detection continuously")
    dm.add_argument("--once", action="store_true", help="run each job once and exit")
    h = sub.add_parser("history", help="list runs")
    h.add_argument("--limit", type=int, default=10)
    h.add_argument("--kind", choices=["audit", "detect"])
    sh = sub.add_parser("show", help="findings of one run")
    sh.add_argument("run_id", type=int)
    sh.add_argument("--logs", action="store_true")
    sh.add_argument("--format", choices=["text", "json"], default="text")
    df = sub.add_parser("diff", help="new/resolved findings between two runs")
    df.add_argument("old", type=int)
    df.add_argument("new", type=int)
    tl = sub.add_parser("timeline", help="audit findings + anomalies on one time axis")
    tl.add_argument("--hours", type=float, default=24)
    tl.add_argument("--min-severity", choices=SEVERITIES, default="low")
    tl.add_argument("--limit", type=int, default=100)
    sub.add_parser("config", help="print the effective settings")
    dd = sub.add_parser("demo", help="write synthetic normal.log / attack.log")
    dd.add_argument("--out-dir", default="demo")
    return p


COMMANDS = {"audit": cmd_audit, "train": cmd_train, "detect": cmd_detect, "daemon": cmd_daemon, "history": cmd_history,
            "show": cmd_show, "diff": cmd_diff, "timeline": cmd_timeline, "demo": cmd_demo}


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    daemon = args.cmd == "daemon"
    logging.basicConfig(level=logging.INFO if daemon else logging.WARNING,
                        format="%(asctime)s %(levelname)s %(message)s" if daemon else "%(levelname)s %(message)s")
    try:
        settings = load_settings(args.config)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 1
    if args.db:
        settings.db = args.db
    if args.cmd == "config":
        print(describe(settings))
        return 0
    if args.cmd == "demo":
        return cmd_demo(args, settings, None) or 0
    db = Database(settings.db)
    try:
        return COMMANDS[args.cmd](args, settings, db) or 0
    except (ValueError, FileNotFoundError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        try:
            db.close()
        except Exception:
            pass
