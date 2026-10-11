"""Ownership / permission audit of critical files (and world-writable files in /etc)."""
import glob
import logging
import os
import stat

from ..registry import register
from ..models import Config, Finding

log = logging.getLogger("sentinel.audit.permissions")

# (path, most permissive mode allowed, contains secrets?)
CRITICAL = [
    ("/etc", 0o755, False),
    ("/etc/passwd", 0o644, False),
    ("/etc/group", 0o644, False),
    ("/etc/shadow", 0o640, True),
    ("/etc/gshadow", 0o640, True),
    ("/etc/security/opasswd", 0o600, True),
    ("/etc/sudoers", 0o440, True),
    ("/etc/sudoers.d", 0o750, True),
    ("/etc/ssh/sshd_config", 0o644, False),
    ("/etc/crontab", 0o644, False),
    ("/etc/cron.d", 0o755, False),
    ("/etc/fstab", 0o644, False),
    ("/root", 0o700, True),
]


def check_path(cfg: Config, path: str, max_mode: int, secret: bool) -> list:
    try:
        st = os.stat(cfg.path(path))
    except FileNotFoundError:
        return []
    except PermissionError:
        return [Finding("permissions", "info", "Cannot stat path", "", path)]
    out, mode = [], stat.S_IMODE(st.st_mode)
    if st.st_uid != 0:
        out.append(Finding("permissions", "critical", "Critical file not owned by root",
                           f"owner uid={st.st_uid}, mode {mode:04o}", path))
    extra = mode & ~max_mode & 0o777
    if extra:
        if extra & 0o002:
            sev = "critical"
        elif (secret and extra & 0o007) or extra & 0o020:
            sev = "high"
        else:
            sev = "medium"
        out.append(Finding("permissions", sev, "Permissions too permissive",
                           f"mode {mode:04o}, expected at most {max_mode:04o}", path))
    return out


def _world_writable_in_etc(cfg: Config, limit: int = 50) -> list:
    out = []
    for root, dirs, files in os.walk(cfg.path("/etc")):
        for name in dirs + files:
            full = os.path.join(root, name)
            try:
                st = os.lstat(full)
            except OSError:
                continue
            if stat.S_ISLNK(st.st_mode) or not st.st_mode & stat.S_IWOTH:
                continue
            if stat.S_ISDIR(st.st_mode) and st.st_mode & stat.S_ISVTX:
                continue  # sticky dirs (like /tmp) are fine
            rel = "/" + os.path.relpath(full, cfg.host_root)
            out.append(Finding("permissions", "high", "World-writable path in /etc",
                               f"mode {stat.S_IMODE(st.st_mode):04o}", rel))
            if len(out) >= limit:
                return out
    return out


@register("permissions")
def run(cfg: Config) -> list:
    out = []
    targets = list(CRITICAL)
    for key in glob.glob(cfg.path("/etc/ssh/ssh_host_*_key")):
        targets.append(("/" + os.path.relpath(key, cfg.host_root), 0o600, True))
    for path, max_mode, secret in targets:
        out += check_path(cfg, path, max_mode, secret)
    out += _world_writable_in_etc(cfg)
    log.info("checked %d critical paths", len(targets))
    return out
