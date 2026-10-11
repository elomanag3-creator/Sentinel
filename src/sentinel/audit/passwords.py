"""Account / password-policy checks: /etc/passwd, /etc/shadow, /etc/login.defs, sshd_config."""
import glob
import logging

from ..registry import register
from ..models import Config, Finding

log = logging.getLogger("sentinel.audit.passwords")


def _read(cfg: Config, path: str):
    try:
        with open(cfg.path(path), encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except FileNotFoundError:
        log.info("%s not found, skipping", path)
        return None


def _passwd(cfg, out):
    text = _read(cfg, "/etc/passwd")
    login_users = set()
    for line in (text or "").splitlines():
        p = line.split(":")
        if len(p) < 7 or line.startswith("#"):
            continue
        user, pw, uid, shell = p[0], p[1], p[2], p[6]
        if not shell.endswith(("nologin", "false")):
            login_users.add(user)
        if uid == "0" and user != "root":
            out.append(Finding("passwords", "critical", "Extra account with UID 0", "Acts as root", user))
        if pw == "":
            out.append(Finding("passwords", "critical", "Account with empty password field in /etc/passwd", "", user))
        elif pw not in ("x", "*", "!"):
            out.append(Finding("passwords", "high", "Password hash stored in world-readable /etc/passwd", "", user))
    return login_users


def _shadow(cfg, login_users, out):
    try:
        text = _read(cfg, "/etc/shadow")
    except PermissionError:
        out.append(Finding("passwords", "info", "Cannot read /etc/shadow", "Run as root for the full password audit", "/etc/shadow"))
        return
    for line in (text or "").splitlines():
        p = line.split(":")
        if len(p) < 5 or line.startswith("#"):
            continue
        user, h, max_days = p[0], p[1], p[4]
        if h == "":
            out.append(Finding("passwords", "critical", "Account has NO password", "", user))
            continue
        if h[0] in "!*":  # locked / no password login
            continue
        if h.startswith("$1$"):
            out.append(Finding("passwords", "high", "Password hashed with MD5-crypt", "Force a password change (yescrypt/sha512)", user))
        elif h.startswith("$5$"):
            out.append(Finding("passwords", "low", "Password hashed with SHA-256-crypt", "Prefer yescrypt or sha512", user))
        elif not h.startswith("$"):
            out.append(Finding("passwords", "high", "Password hashed with legacy DES-crypt", "", user))
        if user in login_users and max_days in ("", "99999"):
            out.append(Finding("passwords", "low", "Password never expires", "", user))


def _login_defs(cfg, out):
    text = _read(cfg, "/etc/login.defs")
    if text is None:
        return
    val = None
    for line in text.splitlines():
        p = line.split()
        if len(p) >= 2 and p[0] == "PASS_MAX_DAYS":
            val = p[1]
    if val is None or not val.isdigit() or int(val) > 365:
        out.append(Finding("passwords", "low", "PASS_MAX_DAYS not set or > 365", f"value: {val}", "/etc/login.defs"))


def _sshd(cfg, out):
    texts = []
    for f in sorted(glob.glob(cfg.path("/etc/ssh/sshd_config.d/*.conf"))):
        with open(f, errors="replace") as fh:
            texts.append(fh.read())
    main = _read(cfg, "/etc/ssh/sshd_config")
    if main is None and not texts:
        return
    texts.append(main or "")
    opts = {}
    for text in texts:                       # sshd: first value wins; stop at Match blocks
        for raw in text.splitlines():
            line = raw.strip().replace("=", " ", 1)
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if parts[0].lower() == "match":
                break
            opts.setdefault(parts[0].lower(), (parts[1] if len(parts) > 1 else "").strip().lower())
    t = "/etc/ssh/sshd_config"
    if opts.get("permitemptypasswords") == "yes":
        out.append(Finding("passwords", "critical", "SSH allows empty passwords", "", t))
    if opts.get("permitrootlogin") == "yes":
        out.append(Finding("passwords", "high", "SSH root login with password allowed", "", t))
    if opts.get("passwordauthentication", "yes") == "yes":
        out.append(Finding("passwords", "low", "SSH password authentication enabled", "Prefer key-based auth", t))


@register("passwords")
def run(cfg: Config) -> list:
    out = []
    users = _passwd(cfg, out)
    _shadow(cfg, users, out)
    _login_defs(cfg, out)
    _sshd(cfg, out)
    return out
