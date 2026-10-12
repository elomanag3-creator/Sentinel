"""Settings: defaults < TOML file < environment < CLI flags. TOML is parsed with the stdlib (Python 3.11+)."""
import os
import tomllib
from dataclasses import dataclass, field, fields

from .models import Config

ETC = "/etc/sentinel/sentinel.toml"
MAP = {  # (toml section, key) -> Settings attribute
    ("general", "db"): "db", ("general", "host_root"): "host_root",
    ("audit", "checks"): "checks", ("audit", "allow_ports"): "allow_ports",
    ("audit", "refresh_index"): "refresh_index", ("audit", "interval"): "audit_interval",
    ("detect", "files"): "files", ("detect", "window"): "window",
    ("detect", "contamination"): "contamination", ("detect", "model"): "model",
    ("detect", "interval"): "detect_interval", ("detect", "lookback_hours"): "lookback_hours",
    ("detect", "novelty"): "novelty",
    ("api", "host"): "api_host", ("api", "port"): "api_port",
    ("api", "token"): "api_token", ("api", "actions"): "api_actions",
}


class ConfigError(Exception):
    pass


@dataclass
class Settings:
    db: str = "data/sentinel.db"
    host_root: str = "/"
    checks: list = field(default_factory=lambda: ["ports", "passwords", "packages", "permissions"])
    allow_ports: list = field(default_factory=list)
    refresh_index: bool = False
    audit_interval: int = 6 * 3600
    files: list = field(default_factory=list)
    window: int = 300
    contamination: float = 0.01
    model: str = "models/model.npz"
    detect_interval: int = 300
    lookback_hours: float = 24
    novelty: bool = True
    api_host: str = "127.0.0.1"      # loopback by default; anything else requires a token
    api_port: int = 8080
    api_token: str = ""              # empty = no auth (loopback only) and no POST actions
    api_actions: bool = True         # allow POST /api/actions/* (only effective when a token is set)

    def audit_config(self) -> Config:
        return Config(self.host_root, {int(p) for p in self.allow_ports}, self.refresh_index)


def load_settings(path: str = None) -> Settings:
    s = Settings()
    path = path or os.environ.get("SENTINEL_CONFIG")
    if path:
        if not os.path.exists(path):
            raise ConfigError(f"config file not found: {path}")
        _apply_toml(s, path)
    else:
        for cand in ("sentinel.toml", ETC):
            if os.path.exists(cand):
                _apply_toml(s, cand)
                break
    for env, attr in (("SENTINEL_DB", "db"), ("SENTINEL_MODEL", "model"), ("SENTINEL_HOST_ROOT", "host_root"),
                      ("SENTINEL_API_TOKEN", "api_token")):
        if os.environ.get(env):
            setattr(s, attr, os.environ[env])
    return s


def _apply_toml(s: Settings, path: str) -> None:
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: invalid TOML: {exc}")
    for section, table in data.items():
        if not isinstance(table, dict):
            raise ConfigError(f"{path}: top-level key '{section}' must be a [section]")
        for key, value in table.items():
            attr = MAP.get((section, key))
            if attr is None:
                raise ConfigError(f"{path}: unknown option [{section}] {key}")
            expected = type(getattr(s, attr))
            if expected is float and isinstance(value, int) and not isinstance(value, bool):
                value = float(value)
            if not isinstance(value, expected):
                raise ConfigError(f"{path}: [{section}] {key} must be {expected.__name__}")
            setattr(s, attr, value)


def describe(s: Settings) -> str:
    def show(f):
        v = getattr(s, f.name)
        return "<set>" if f.name == "api_token" and v else v   # never print the secret
    return "\n".join(f"{f.name} = {show(f)!r}" for f in fields(s))
