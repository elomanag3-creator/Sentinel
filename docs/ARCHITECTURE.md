# Architecture notes

- `models.py` - `Finding` (audit finding *or* anomaly), `Config` (what checks see).
- `registry.py` - checks register with `@register(name)`; third parties via the `sentinel.checks` entry point.
- `db.py` - SQLite, WAL mode, migrations, `capture_logs()` stores every `sentinel.*` log line with its run.
- `audit/` - one module per check; `runner.py` isolates crashes (a failing check becomes an `info` finding).
- `detect/` - `parser` (templates), `features` (windows), `model` (IsolationForest + novelty), `sources` (files / audit history),
  `runner` (train/detect/persist). Naive datetimes inside `detect/` mean *local wall clock*; the DB always stores UTC.
- `daemon.py` - single loop, two jobs; model auto-train and reload when the file changes; only new anomalies are reported.
- `cli.py` - thin: parse args, call runners, print.

Planned: `api/` (read-only FastAPI over the same DB), `web/`, `agent/` (push to a central server), alert sinks.
