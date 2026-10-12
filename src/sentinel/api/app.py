"""HTTP API + dashboard over the same SQLite database the CLI and daemon write to.

Design rules:
- Reads are the default. POST actions (run audit / detect / train) exist only when a token is configured.
- Binding to anything but loopback requires a token (enforced in `sentinel serve`).
- Log lines and finding details can contain attacker-controlled text: the dashboard renders them with
  textContent only, and a strict CSP forbids inline scripts.
"""
import dataclasses
import hmac
import logging
import os
from contextlib import contextmanager
from importlib import resources

from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from .. import __version__
from ..config import Settings
from ..db import RUN_LOCK, Database
from ..models import SEVERITIES

log = logging.getLogger("sentinel.api")
PUBLIC = {"/api/health", "/api/info"}
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
STATIC = {"/": ("index.html", "text/html; charset=utf-8"), "/app.js": ("app.js", "text/javascript; charset=utf-8"),
          "/style.css": ("style.css", "text/css; charset=utf-8")}


class BadRequest(Exception):
    pass


class Busy(Exception):
    pass


def _num(request, name, default, lo, hi, cast=float):
    raw = request.query_params.get(name)
    if raw is None or raw == "":
        return default
    try:
        v = cast(raw)
    except ValueError:
        raise BadRequest(f"'{name}' must be a number")
    if not lo <= v <= hi:
        raise BadRequest(f"'{name}' must be between {lo} and {hi}")
    return v


def _severity(request, name, default):
    v = request.query_params.get(name, default)
    if v not in SEVERITIES:
        raise BadRequest(f"'{name}' must be one of {', '.join(SEVERITIES)}")
    return v


def create_app(settings: Settings, allowed_hosts=None) -> Starlette:
    token = settings.api_token
    actions_enabled = bool(token) and settings.api_actions

    @contextmanager
    def db():
        d = Database(settings.db)
        try:
            yield d
        finally:
            d.close()

    # -- middleware ---------------------------------------------------------------------------
    class Guard(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            path = request.url.path
            if token and path.startswith("/api/") and path not in PUBLIC:
                given = request.headers.get("authorization", "")
                ok = given.startswith("Bearer ") and hmac.compare_digest(given[7:].encode(), token.encode())
                if not ok:
                    return JSONResponse({"error": "unauthorized"}, 401, {"WWW-Authenticate": "Bearer"})
            resp = await call_next(request)
            resp.headers["Content-Security-Policy"] = CSP
            resp.headers["X-Content-Type-Options"] = "nosniff"
            resp.headers["X-Frame-Options"] = "DENY"
            resp.headers["Referrer-Policy"] = "no-referrer"
            if path.startswith("/api/"):
                resp.headers["Cache-Control"] = "no-store"
            return resp

    # -- static -------------------------------------------------------------------------------
    def static(request: Request):
        name, ctype = STATIC[request.url.path]
        data = (resources.files("sentinel.api") / "static" / name).read_bytes()
        return Response(data, media_type=ctype)

    # -- read endpoints (sync handlers run in Starlette's threadpool) --------------------------
    def health(request):
        return JSONResponse({"status": "ok", "version": __version__})

    def info(request):
        return JSONResponse({"version": __version__, "auth_required": bool(token), "actions_enabled": actions_enabled})

    def summary(request):
        with db() as d:
            audit, detect = (d.list_runs(1, k) for k in ("audit", "detect"))
            audit, detect = (dict(x[0]) if x else None for x in (audit, detect))
            return JSONResponse({
                "hostname": (audit or detect or {}).get("hostname", ""),
                "latest_audit": audit,
                "latest_audit_counts": d.severity_counts(audit["id"]) if audit else {},
                "latest_detect": detect,
                "anomalies_24h": d.anomaly_counts(24),
                "runs_total": d.conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0],
            })

    def runs(request):
        kind = request.query_params.get("kind")
        if kind not in (None, "", "audit", "detect"):
            raise BadRequest("'kind' must be audit or detect")
        limit = _num(request, "limit", 25, 1, 500, int)
        with db() as d:
            return JSONResponse([dict(r) for r in d.list_runs(limit, kind or None)])

    def _run_id(request):
        try:
            return int(request.path_params["run_id"])
        except ValueError:
            raise BadRequest("run id must be an integer")

    def run_detail(request):
        rid = _run_id(request)
        with db() as d:
            run = d.get_run(rid)
            if not run:
                return JSONResponse({"error": f"no run #{rid}"}, 404)
            return JSONResponse({"run": dict(run), "findings": [dict(f) for f in d.get_findings(rid)]})

    def run_logs(request):
        rid = _run_id(request)
        with db() as d:
            if not d.get_run(rid):
                return JSONResponse({"error": f"no run #{rid}"}, 404)
            return JSONResponse([dict(x) for x in d.get_logs(rid)])

    def diff(request):
        old, new = _num(request, "old", None, 1, 2**62, int), _num(request, "new", None, 1, 2**62, int)
        if old is None or new is None:
            raise BadRequest("'old' and 'new' run ids are required")
        with db() as d:
            for rid in (old, new):
                if not d.get_run(rid):
                    return JSONResponse({"error": f"no run #{rid}"}, 404)
            added, resolved = d.diff(old, new)
            return JSONResponse({"old": old, "new": new, "new_findings": [dict(r) for r in added],
                                 "resolved": [dict(r) for r in resolved]})

    def timeline(request):
        hours = _num(request, "hours", 24, 0.1, 24 * 365)
        sev = _severity(request, "min_severity", "low")
        limit = _num(request, "limit", 200, 1, 2000, int)
        with db() as d:
            return JSONResponse([dict(r) for r in d.timeline(hours, sev, limit)])

    def config(request):
        data = dataclasses.asdict(settings)
        data["api_token"] = "<set>" if data["api_token"] else ""      # never expose the secret
        return JSONResponse({"settings": data})

    # -- actions (token required) ----------------------------------------------------------------
    async def action(request: Request):
        if not actions_enabled:
            return JSONResponse({"error": "actions are disabled (set [api] token to enable them)"}, 403)
        name = request.path_params["name"]
        if name not in ("audit", "detect", "train"):
            return JSONResponse({"error": f"unknown action '{name}'"}, 404)
        try:
            body = await request.json() if await request.body() else {}
        except ValueError:
            raise BadRequest("body must be JSON")
        if not isinstance(body, dict):
            raise BadRequest("body must be a JSON object")
        try:
            result = await run_in_threadpool(_perform, name, body)
        except Busy:
            return JSONResponse({"error": "another run is in progress"}, 409)
        except (ValueError, FileNotFoundError, RuntimeError) as exc:
            return JSONResponse({"error": str(exc)}, 400)
        return JSONResponse(result)

    def _perform(name: str, body: dict) -> dict:
        if not RUN_LOCK.acquire(blocking=False):      # taken in the worker thread: the lock is per-thread re-entrant
            raise Busy()
        try:
            return _do(name, body)
        finally:
            RUN_LOCK.release()

    def _do(name: str, body: dict) -> dict:
        with db() as d:
            s = dataclasses.replace(settings)            # never mutate the shared settings
            if name == "audit":
                from ..audit.runner import run_audit
                checks = body.get("checks")
                if checks is not None and not (isinstance(checks, list) and all(isinstance(c, str) for c in checks)):
                    raise ValueError("'checks' must be a list of names")
                rid = run_audit(d, s, checks or None)
                run = d.get_run(rid)
                return {"run_id": rid, "total": run["total"], "max_severity": run["max_severity"]}
            if name in ("detect", "train"):
                try:
                    from ..detect import runner
                    from ..detect.model import Detector
                except ImportError as exc:
                    raise RuntimeError(f"needs the ML extras: pip install 'sentinel-monitor[ml]' ({exc})")
                audit_history = bool(body.get("audit_history"))
                if name == "train":
                    return {"trained": runner.train(s, d, audit_history=audit_history)}
                if not os.path.exists(s.model):
                    raise ValueError(f"no model at {s.model} - train first")
                lookback = body.get("lookback_hours", s.lookback_hours)
                if isinstance(lookback, bool) or not isinstance(lookback, (int, float)) or lookback <= 0:
                    raise ValueError("'lookback_hours' must be a positive number")
                rid, anomalies, nwin, nev = runner.detect(s, d, Detector.load(s.model), audit_history=audit_history,
                                                          lookback_hours=lookback, novelty=s.novelty)
                return {"run_id": rid, "anomalies": len(anomalies), "windows": nwin, "events": nev}
            raise ValueError(f"unknown action '{name}'")

    routes = [Route(p, static) for p in STATIC]
    routes += [
        Route("/api/health", health), Route("/api/info", info), Route("/api/summary", summary),
        Route("/api/runs", runs), Route("/api/runs/{run_id}", run_detail), Route("/api/runs/{run_id}/logs", run_logs),
        Route("/api/diff", diff), Route("/api/timeline", timeline), Route("/api/config", config),
        Route("/api/actions/{name:str}", action, methods=["POST"]),
    ]
    middleware = [Middleware(Guard)]
    if allowed_hosts:   # DNS-rebinding protection for the loopback / no-auth setup
        middleware.insert(0, Middleware(TrustedHostMiddleware, allowed_hosts=list(allowed_hosts)))
    handlers = {BadRequest: lambda request, exc: JSONResponse({"error": str(exc)}, 400)}
    return Starlette(routes=routes, middleware=middleware, exception_handlers=handlers)
