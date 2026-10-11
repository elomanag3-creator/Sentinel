"""Log line parsing + template extraction (a tiny Drain-style masking approach)."""
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

SYSLOG = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
                    r"(?P<proc>[^\s:\[]+)(?:\[\d+\])?:\s*(?P<msg>.*)$")
ISO = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?\s+"
                 r"(?P<host>\S+)\s+(?P<proc>[^\s:\[]+)(?:\[\d+\])?:\s*(?P<msg>.*)$")
IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
ERR_RE = re.compile(r"(?i)\b(error|fail(?:ed|ure)?|denied|invalid|refused|fatal|panic|segfault|critical|killed|timeout)\b")

MASKS = [  # order matters
    (re.compile(r"SHA256:\S+"), "SHA256:<HASH>"),
    (IPV4, "<IP>"),
    (re.compile(r"/home/[^/\s;]+"), "/home/<USER>"),
    (re.compile(r"(?i)\b(invalid user|for user|user)\s+(?!<)\S+"), r"\1 <USER>"),
    (re.compile(r"\bfor\s+(?!invalid\b|user\b|<)\S+\s+from\b"), "for <USER> from"),
    (re.compile(r"^(?!<)\S+ : "), "<USER> : "),
    (re.compile(r"\[\s*\d+\.\d+\]"), "[<TS>]"),
    (re.compile(r"\b0x[0-9a-fA-F]+\b|\b[0-9a-fA-F]{12,}\b"), "<HEX>"),
]
NUMBER = (re.compile(r"\b\d+(?:\.\d+)?\b"), "<N>")
# Volatile bits of secaudit findings that must not create a new template every run:
FINDING_MASKS = [(re.compile(r"(update available:)\s*\S+"), r"\1 <PKG>"),
                 (re.compile(r"\b\d+ non-security"), "<N> non-security")]


@dataclass
class Event:
    ts: datetime              # naive datetime (wall clock of the log source)
    host: str
    proc: str
    msg: str
    level: str = "INFO"
    group: Optional[int] = None   # e.g. secaudit run id
    template: str = ""
    ips: tuple = ()

    def finalize(self, mask_numbers: bool = True) -> "Event":
        self.ips = tuple(IPV4.findall(self.msg))
        self.template = templatize(self.proc, self.msg, mask_numbers)
        return self


def templatize(proc: str, msg: str, mask_numbers: bool = True) -> str:
    out = msg
    for rx, rep in MASKS:
        out = rx.sub(rep, out)
    if mask_numbers:
        out = NUMBER[0].sub(NUMBER[1], out)
    else:
        for rx, rep in FINDING_MASKS:
            out = rx.sub(rep, out)
    return f"{proc}: {out}".strip()


def guess_level(msg: str) -> str:
    return "ERROR" if ERR_RE.search(msg) else "INFO"


def _syslog_ts(ts: str, ref: datetime) -> datetime:
    dt = datetime.strptime(f"{ref.year} {ts}", "%Y %b %d %H:%M:%S")
    if dt > ref + timedelta(days=1):       # Dec log read in January
        dt = dt.replace(year=ref.year - 1)
    return dt


def parse_line(line: str, ref: Optional[datetime] = None) -> Optional[Event]:
    ref = ref or datetime.now()
    line = line.rstrip("\n")
    m = SYSLOG.match(line)
    try:
        if m:
            ts = _syslog_ts(re.sub(r"\s+", " ", m["ts"]), ref)
        else:
            m = ISO.match(line)
            if not m:
                return None
            ts = datetime.fromisoformat(m["ts"].replace(" ", "T"))
    except ValueError:
        return None
    return Event(ts, m["host"], m["proc"], m["msg"], guess_level(m["msg"])).finalize()
