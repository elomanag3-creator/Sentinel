"""Turn events into windows and numeric feature vectors."""
import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta

import numpy as np

EPOCH = datetime(1970, 1, 1)
AUTH_FAIL = re.compile(r"(?i)failed password|authentication failure|invalid user|failed publickey|"
                       r"permission denied|maximum authentication attempts")
BASE = ["events", "idle_streak", "distinct_templates", "error_ratio", "auth_failures", "distinct_ips",
        "top_ip_share", "template_entropy", "hour_sin", "hour_cos"]
COUNT_FEATURES = {"events", "idle_streak", "distinct_templates", "auth_failures", "distinct_ips"}


@dataclass
class Window:
    start: datetime
    end: datetime
    events: list
    idle: int = 0          # consecutive empty windows right before this one (log silence)


def build_windows(events, mode="time", window_s=300, fill_gaps=True) -> list:
    """mode='time': fixed buckets (empty ones included so log *silence* is visible).
    mode='group': one window per Event.group (e.g. per secaudit run)."""
    if not events:
        return []
    if mode == "group":
        groups = defaultdict(list)
        for e in events:
            groups[e.group].append(e)
        wins = [Window(min(e.ts for e in v), max(e.ts for e in v), v) for v in groups.values()]
        return sorted(wins, key=lambda w: w.start)
    buckets = defaultdict(list)
    for e in events:
        buckets[int((e.ts - EPOCH).total_seconds() // window_s)].append(e)
    keys = range(min(buckets), max(buckets) + 1) if fill_gaps else sorted(buckets)
    wins = [Window(EPOCH + timedelta(seconds=k * window_s), EPOCH + timedelta(seconds=(k + 1) * window_s),
                   buckets.get(k, [])) for k in keys]
    streak = 0
    for w in wins:
        w.idle = streak
        streak = streak + 1 if not w.events else 0
    return wins[:-1] if len(wins) > 1 else wins   # last bucket is usually still filling up


def fit_vocab(windows, top_k=25) -> list:
    c = Counter(e.template for w in windows for e in w.events)
    return [t for t, _ in c.most_common(top_k)]


def feature_names(vocab) -> list:
    return BASE + [f"tpl:{t[:70]}" for t in vocab]


def count_mask(vocab) -> np.ndarray:
    return np.array([n in COUNT_FEATURES or n.startswith("tpl:") for n in feature_names(vocab)])


def featurize(w: Window, vocab) -> np.ndarray:
    n = len(w.events)
    tc = Counter(e.template for e in w.events)
    ips = Counter(ip for e in w.events for ip in e.ips)
    ang = 2 * math.pi * (w.start.hour * 60 + w.start.minute) / 1440
    entropy = -sum(c / n * math.log(c / n) for c in tc.values()) if n else 0.0
    base = [n, w.idle, len(tc),
            sum(e.level in ("ERROR", "CRITICAL") for e in w.events) / n if n else 0.0,
            sum(bool(AUTH_FAIL.search(e.msg)) for e in w.events),
            len(ips), max(ips.values()) / sum(ips.values()) if ips else 0.0,
            entropy, math.sin(ang), math.cos(ang)]
    return np.array(base + [tc.get(t, 0) for t in vocab], dtype=float)


def matrix(windows, vocab) -> np.ndarray:
    X = np.vstack([featurize(w, vocab) for w in windows])
    m = count_mask(vocab)
    X[:, m] = np.log1p(X[:, m])        # counts are heavy-tailed
    return X
