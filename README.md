# The Sentinel

Lightweight host security monitor in one process and one SQLite database:

- **Audit** - posture checks: exposed ports, password/SSH policy, outdated packages, permissions on critical files.
- **Detect** - unsupervised ML on your logs. Every anomaly explains *why* (`auth_failures high, z=+10.2, top IP 185.220.101.4`).
- **One timeline** - audit findings and anomalies side by side, so "new port opened at 14:02" and "login failures spiked at 14:05" read as one story.

Pure standard library for auditing; scikit-learn only for the ML half (`pip install "sentinel-monitor[ml]"`).
**Use only on systems you own or are authorized to assess.** Status: early alpha (0.1.0).

## Quick start (no root, no real logs needed)
    python3 -m venv .venv && . .venv/bin/activate
    pip install -e ".[ml]"
    sentinel audit                                   # posture audit of this machine (run with sudo for the full picture)
    sentinel demo --out-dir demo                     # synthetic logs: brute force, log silence, reverse shell, crash loop
    sentinel train  --file demo/normal.log
    sentinel detect --file demo/attack.log --lookback 30
    sentinel timeline --hours 48                     # audit findings + anomalies together

## Commands
| Command | What it does |
|---|---|
| `audit` | Run checks now (`--checks`, `--allow-ports 22,443`, `--host-root`, `--fail-on high` -> exit 2) |
| `train` / `detect` | Learn normal / find anomalies. Source: `--file` (log files) or `--audit-history` (past audits, one window per run) |
| `daemon` | Audits every N hours + detection every N minutes, forever (`--once` for a single pass). Trains itself if no model exists yet |
| `timeline` | Everything on one time axis (`--hours`, `--min-severity`) |
| `history`, `show ID [--logs]`, `diff A B` | Browse runs, see run logs, new/resolved findings between two runs |
| `config`, `demo` | Print effective settings / write demo logs |

Use a separate `--model` file per source: a model trained on log files cannot score audit history (and vice versa).

## Configuration
`sentinel.toml` (see `sentinel.example.toml`), looked up via `--config`, `$SENTINEL_CONFIG`, `./sentinel.toml`, `/etc/sentinel/sentinel.toml`.
Precedence: defaults < file < environment (`SENTINEL_DB`, `SENTINEL_MODEL`, `SENTINEL_HOST_ROOT`) < CLI flags. Typos in the file are errors, not silently ignored.

## Docker
    # edit docker/sentinel.toml first (allowed ports, log path)
    docker compose up -d --build
    docker compose logs -f sentinel
    docker compose run --rm sentinel timeline
The container is root, with the host mounted read-only at `/host`, host network and PID namespace. Nothing on the host is modified.
(The image and compose file are untested in CI so far - see Status.)

## How it works
    sentinel audit / daemon            sentinel train / detect
        |  checks (plugins)                |  parse -> templates -> windows -> features
        v                                  v  IsolationForest + never-seen-pattern detector
    runs + findings(source=audit)   runs + findings(source=anomaly)        <- same SQLite DB
                      \\                   /
                       `-- timeline / diff / history / (API + dashboard: next)`

- Log lines are masked into *templates* (IPs, users, numbers removed). Windows (default 5 min, empty ones kept) get features:
  event count, idle streak, error ratio, auth failures, distinct IPs, top-IP share, entropy, time of day, top-25 template counts.
- Severity is graded by the strongest deviation (z-score); never-seen patterns are raised higher if they look like auth failures or
  suspicious commands (`nc -e`, `curl | sh`, root password login...).
- Model files are NumPy + JSON (`allow_pickle=False`); the forest is rebuilt deterministically on load.
- Schema changes go through numbered migrations (`PRAGMA user_version`).

## Write your own check
    # mypkg/checks.py
    from sentinel.models import Config, Finding
    def run(cfg: Config) -> list:
        return [Finding("mycheck", "medium", "Something is off", "details", "/some/target")]

    # mypkg's pyproject.toml
    [project.entry-points."sentinel.checks"]
    mycheck = "mypkg.checks:run"
Then add `"mycheck"` to `[audit] checks`. Use `cfg.path("/etc/x")` so it works on a mounted host root.

## Limits (honest notes)
- Unsupervised ML finds *unusual*, not *malicious*; expect some low-severity noise and tune `contamination`. Train on a clean period.
- Linux only. TCP only (no UDP yet). Package checks: apt, apk, dnf; no CVE matching yet.
- Syslog lines carry no year/timezone: current year and host-local wall clock are assumed.
- Tested on Debian/Ubuntu-style systems only. Not a replacement for a full SIEM/EDR.

## Roadmap
API + dashboard -> multi-host agents and alerts (Slack/mail/webhook) -> CVE matching (OSV), SUID inventory, container audits, journald/JSON logs.


