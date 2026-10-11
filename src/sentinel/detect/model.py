"""IsolationForest over window features + a separate "never seen before" template detector.

Model files are plain numpy arrays + JSON (np.savez, allow_pickle=False) - no pickle. The forest is not stored:
the training matrix is, and the (seeded, deterministic) forest is rebuilt on load.
"""
import json
import logging
import re
from collections import Counter, defaultdict
from dataclasses import dataclass

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from .features import AUTH_FAIL, build_windows, count_mask, feature_names, fit_vocab, matrix

log = logging.getLogger("sentinel.detect")
FORMAT = 1
SUSPICIOUS = re.compile(r"(?i)\bnc(at)? .*-e\b|/dev/tcp/|\bbase64 -d|chmod [0-7]*7[0-7]*7 |(curl|wget) [^|;]*\|\s*(ba)?sh|"
                        r"Accepted password for root|authorized_keys|useradd|/etc/shadow")
MIN_WINDOWS = {"time": 50, "group": 10}


@dataclass
class Anomaly:
    kind: str            # "window" | "new_template"
    severity: str        # low | medium | high | critical
    start: object        # naive local datetime
    end: object
    score: float
    title: str
    detail: str
    host: str = ""


def severity_from_z(z: float) -> str:
    """Grade by the strongest single-feature deviation (IsolationForest scores saturate, z-scores don't)."""
    return "low" if z < 4 else "medium" if z < 7 else "high" if z < 12 else "critical"


class Detector:
    def __init__(self, mode="time", window_s=300, contamination=0.01, top_k=25, seed=42):
        self.mode, self.window_s, self.contamination = mode, window_s, contamination
        self.top_k, self.seed, self.fill_gaps = top_k, seed, True

    # ---- training -------------------------------------------------------------------------
    def _refit(self, X):
        self.scaler = StandardScaler().fit(X)
        Z = self.scaler.transform(X)
        self.iso = IsolationForest(n_estimators=300, random_state=self.seed).fit(Z)
        s = -self.iso.score_samples(Z)
        self.threshold = float(np.quantile(s, 1 - self.contamination))
        self.base = float(np.median(s))

    def fit(self, events, fill_gaps=True) -> dict:
        wins = build_windows(events, self.mode, self.window_s, fill_gaps)
        need = MIN_WINDOWS[self.mode]
        if len(wins) < need:
            raise ValueError(f"only {len(wins)} windows to learn from, need at least {need}. "
                             "Use more history (or a smaller window).")
        self.fill_gaps = fill_gaps
        self.vocab = fit_vocab(wins, self.top_k)
        self.mask, self.names = count_mask(self.vocab), feature_names(self.vocab)
        self.X_train = matrix(wins, self.vocab)
        self._refit(self.X_train)
        self.seen = {e.template for e in events}
        return {"windows": len(wins), "events": len(events), "templates": len(self.seen),
                "threshold": round(self.threshold, 4)}

    # ---- detection ------------------------------------------------------------------------
    def detect(self, events, novelty=True, max_novel=20) -> tuple:
        wins = build_windows(events, self.mode, self.window_s, self.fill_gaps)
        if not wins:
            return [], 0
        Z = self.scaler.transform(matrix(wins, self.vocab))
        scores = -self.iso.score_samples(Z)
        out = [self._window_anomaly(w, float(s), z) for w, s, z in zip(wins, scores, Z) if s > self.threshold]
        if novelty:
            out += self._novel(events, max_novel)
        out.sort(key=lambda a: a.start)
        return out, len(wins)

    def _window_anomaly(self, w, score, z) -> Anomaly:
        reasons = []
        zz = np.array([0.0 if n.startswith("hour_") else abs(v) for n, v in zip(self.names, z)])
        for i in np.argsort(-zz)[:3]:
            if zz[i] < 2.5:
                continue
            raw = z[i] * self.scaler.scale_[i] + self.scaler.mean_[i]
            raw = float(np.expm1(raw)) if self.mask[i] else float(raw)
            reasons.append(f"{self.names[i]} {'high' if z[i] > 0 else 'low'} (value {raw:.2f}, z={z[i]:+.1f})")
        extra = []
        if w.events:
            tpl, n = Counter(e.template for e in w.events).most_common(1)[0]
            extra.append(f"top pattern x{n}: {tpl[:110]}")
            ips = Counter(ip for e in w.events for ip in e.ips)
            if ips:
                ip, c = ips.most_common(1)[0]
                extra.append(f"top IP {ip} in {c} events")
        title = "Unusual log activity" + (f": {reasons[0].split(' (')[0]}" if reasons else "")
        return Anomaly("window", severity_from_z(float(zz.max())), w.start, w.end, round(score, 4), title,
                       "; ".join(reasons + extra) or "combination of features is unusual",
                       w.events[0].host if w.events else "")

    def _novel(self, events, max_items) -> list:
        groups = defaultdict(list)
        for e in events:
            if e.template not in self.seen:
                groups[e.template].append(e)
        out = []
        for tpl, evs in sorted(groups.items(), key=lambda kv: -len(kv[1]))[:max_items]:
            bad = any(e.level in ("ERROR", "CRITICAL") or AUTH_FAIL.search(e.msg) for e in evs)
            crit = any(e.level == "CRITICAL" or SUSPICIOUS.search(e.msg) for e in evs)
            out.append(Anomaly("new_template", "high" if crit else "medium" if bad else "low",
                               evs[0].ts, evs[-1].ts, 0.0, "Never-seen log pattern",
                               f"{len(evs)}x: {tpl[:160]}", evs[0].host))
        return out

    # ---- persistence (no pickle) ----------------------------------------------------------
    def save(self, path: str) -> None:
        meta = {"format": FORMAT, "mode": self.mode, "window_s": self.window_s, "contamination": self.contamination,
                "top_k": self.top_k, "seed": self.seed, "fill_gaps": self.fill_gaps,
                "vocab": self.vocab, "seen": sorted(self.seen)}
        with open(path, "wb") as fh:
            np.savez_compressed(fh, X=self.X_train, meta=np.array(json.dumps(meta)))

    @classmethod
    def load(cls, path: str) -> "Detector":
        with np.load(path, allow_pickle=False) as z:
            X, meta = z["X"], json.loads(str(z["meta"]))
        if meta.get("format") != FORMAT:
            raise ValueError(f"unsupported model format {meta.get('format')!r}; retrain with `sentinel train`")
        d = cls(meta["mode"], meta["window_s"], meta["contamination"], meta["top_k"], meta["seed"])
        d.fill_gaps, d.vocab, d.seen = meta["fill_gaps"], meta["vocab"], set(meta["seen"])
        d.mask, d.names, d.X_train = count_mask(d.vocab), feature_names(d.vocab), X
        d._refit(X)
        return d
