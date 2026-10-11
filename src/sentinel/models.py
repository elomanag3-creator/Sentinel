import os
from dataclasses import dataclass, field
from typing import Optional

SEVERITIES = ["info", "low", "medium", "high", "critical"]


def sev_rank(sev: str) -> int:
    return SEVERITIES.index(sev)


@dataclass
class Finding:
    """One row in the unified timeline: either an audit finding or a detected anomaly."""
    check: str
    severity: str
    title: str
    detail: str = ""
    target: str = ""
    source: str = "audit"                 # "audit" | "anomaly"
    window_start: Optional[str] = None    # anomalies only (UTC ISO)
    window_end: Optional[str] = None
    score: Optional[float] = None


@dataclass
class Config:
    """What an audit check sees."""
    host_root: str = "/"          # "/" = this machine; "/host" = bind-mounted host (Docker)
    allow_ports: set = field(default_factory=set)
    refresh_index: bool = False

    def path(self, p: str) -> str:
        return os.path.join(self.host_root, p.lstrip("/"))
