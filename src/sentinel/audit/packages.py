"""Outdated packages for Debian/Ubuntu (apt), Alpine (apk) and RHEL/Fedora (dnf).

Uses a *simulated* upgrade, so nothing is ever installed. When auditing a mounted host
(host_root != "/"), the package manager is executed inside it via chroot.
"""
import glob
import logging
import os
import re
import subprocess
import time

from ..registry import register
from ..models import Config, Finding

log = logging.getLogger("sentinel.audit.packages")
APT_INST = re.compile(r"^Inst (\S+) \[([^\]]+)\] \((\S+) (.*)\)")
APK_LINE = re.compile(r"^(.+?)-(\d\S*)\s+<\s+(\S+)")


def _run(cfg: Config, cmd: list, timeout: int = 180):
    if cfg.host_root not in ("/", ""):
        cmd = ["chroot", cfg.host_root] + cmd
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.warning("command %s failed: %s", cmd[0], exc)
        return None


def detect(cfg: Config):
    if os.path.exists(cfg.path("/var/lib/dpkg/status")):
        return "apt"
    if os.path.exists(cfg.path("/lib/apk/db/installed")):
        return "apk"
    if any(os.path.isdir(cfg.path(p)) for p in ("/var/lib/rpm", "/usr/lib/sysimage/rpm")):
        return "dnf"
    return None


def _apt(cfg):
    if cfg.refresh_index:
        _run(cfg, ["apt-get", "update"], 300)
    r = _run(cfg, ["apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade"])
    if r is None or r.returncode != 0:
        return None, "apt-get simulation failed"
    ups = []
    for line in r.stdout.splitlines():
        m = APT_INST.match(line)
        if m:
            ups.append((m[1], m[2], m[3], "security" in line.lower()))
    return ups, None


def _apk(cfg):
    if cfg.refresh_index:
        _run(cfg, ["apk", "update"])
    r = _run(cfg, ["apk", "version", "-l", "<"])
    if r is None or r.returncode != 0:
        return None, "apk version failed"
    return [(m[1], m[2], m[3], False) for m in map(APK_LINE.match, r.stdout.splitlines()) if m], None


def _dnf_names(r):
    rows = {}
    if r is not None:
        for line in r.stdout.splitlines():
            p = line.split()
            if len(p) == 3 and "." in p[0]:
                rows[p[0]] = p[1]
    return rows


def _dnf(cfg):
    allr = _run(cfg, ["dnf", "-q", "check-update"])
    if allr is None or allr.returncode not in (0, 100):
        return None, "dnf check-update failed"
    sec = _dnf_names(_run(cfg, ["dnf", "-q", "check-update", "--security"]))
    return [(n, "?", v, n in sec) for n, v in _dnf_names(allr).items()], None


def _stale_index(cfg):
    files = glob.glob(cfg.path("/var/lib/apt/lists/*"))
    if files and time.time() - max(os.path.getmtime(f) for f in files) > 14 * 86400:
        return Finding("packages", "low", "Package index older than 14 days",
                       "Results may miss new updates; run with --refresh-index or `apt-get update`", "apt")
    return None


@register("packages")
def run(cfg: Config) -> list:
    mgr = detect(cfg)
    if mgr is None:
        return [Finding("packages", "info", "No supported package manager found (apt/apk/dnf)")]
    log.info("package manager: %s", mgr)
    ups, err = {"apt": _apt, "apk": _apk, "dnf": _dnf}[mgr](cfg)
    if err:
        return [Finding("packages", "info", err, "Is the package manager available / network reachable?", mgr)]
    out = []
    if mgr == "apt" and (f := _stale_index(cfg)):
        out.append(f)
    for name, cur, new, security in ups:
        if security:
            out.append(Finding("packages", "high", f"Security update available: {name}", f"{cur} -> {new}", name))
    normal = [u for u in ups if not u[3]]
    if normal:
        sev = "medium" if len(normal) > 20 else "low"
        names = ", ".join(u[0] for u in normal[:15]) + (" ..." if len(normal) > 15 else "")
        out.append(Finding("packages", sev, f"{len(normal)} non-security updates pending", names, mgr))
    return out
