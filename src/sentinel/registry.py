"""Audit checks are plugins: built-ins register themselves; third parties use the `sentinel.checks` entry point."""
import logging
from importlib import import_module, metadata
from typing import Callable, Dict

log = logging.getLogger("sentinel.registry")
CHECKS: Dict[str, Callable] = {}
BUILTIN = ("ports", "passwords", "packages", "permissions")


def register(name: str):
    def deco(fn):
        CHECKS[name] = fn
        return fn
    return deco


def load_checks() -> Dict[str, Callable]:
    """A check is a function `run(cfg: sentinel.models.Config) -> list[Finding]`."""
    for mod in BUILTIN:
        import_module(f"sentinel.audit.{mod}")
    try:
        eps = metadata.entry_points(group="sentinel.checks")
    except TypeError:                       # very old importlib.metadata
        eps = metadata.entry_points().get("sentinel.checks", [])
    for ep in eps:
        try:
            CHECKS[ep.name] = ep.load()
        except Exception:
            log.exception("could not load check plugin %s", ep.name)
    return CHECKS
