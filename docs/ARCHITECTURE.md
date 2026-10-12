# Architecture notes

- `models.py` - `Finding` (audit finding *or* anomaly), `Config` (what checks see).
- `registry.py` - checks register with `@register(name)`; third parties via the `sentinel.checks` entry point.
- `db.py` - SQLite, WAL mode, migrations, `capture_logs()` stores every `sentinel.*` log line with its run.
- `audit/` - one module per check; `runner.py` isolates crashes (a failing check becomes an `info` finding).
- `detect/` - `parser` (templates), `features` (windows), `model` (IsolationForest + novelty), `sources` (files / audit history),
  `runner` (train/detect/persist). Naive datetimes inside `detect/` mean *local wall clock*; the DB always stores UTC.
- `daemon.py` - single loop, two jobs; model auto-train and reload when the file changes; only new anomalies are reported.
- `cli.py` - thin: parse args, call runners, print.

- `api/app.py` - Starlette app over the same DB (`create_app(settings)`): JSON endpoints, static dashboard in `api/static/`
  (no build step, no inline JS). Each request opens its own SQLite connection (WAL: readers never block the writer).
  POST actions are only routed when a token is configured, take `db.RUN_LOCK` non-blockingly (409 when busy) and run in a worker thread.
- `db.RUN_LOCK` - serialises audit/detect runs in one process (`capture_logs` attaches to the global `sentinel` logger, so
  the daemon thread and an API action must not overlap).
- `detect/model.py` - IsolationForest + z-score gate (`STRONG_Z`) + never-seen-template detector.

Planned: `agent/` (push to a central server), alert sinks (Slack/mail/webhook), CVE matching.
