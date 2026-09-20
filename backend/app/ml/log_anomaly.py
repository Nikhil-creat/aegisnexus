"""Unsupervised anomaly detection on activity windows (Isolation Forest).

A window summarises a few minutes of activity for one service or host. The model is
fitted on a synthetic *benign* baseline only, so it flags anything that is rare
compared with that baseline (it never needs attack labels). Swap `make_log_window`
for features built from your own auth, proxy or NetFlow logs.
"""
from __future__ import annotations

import numpy as np
from sklearn.ensemble import IsolationForest

FEATURES = ["events_per_min", "failed_ratio", "distinct_users", "distinct_ips", "off_hours_ratio", "mb_out"]
LOG_KINDS = ["benign", "credential_stuffing", "data_exfil", "off_hours_insider"]


def make_log_window(kind: str, rng: np.random.Generator) -> np.ndarray:
    if kind == "benign":
        v = [rng.normal(40, 8), rng.beta(1, 30), rng.normal(12, 3), rng.normal(10, 3), rng.beta(1.5, 12), rng.normal(30, 8)]
    elif kind == "credential_stuffing":
        v = [rng.normal(400, 60), rng.normal(.85, .05), rng.normal(150, 30), rng.normal(25, 8), rng.normal(.2, .05), rng.normal(35, 8)]
    elif kind == "data_exfil":
        v = [rng.normal(45, 8), rng.beta(1, 30), rng.normal(3, 1), rng.normal(2, .7), rng.normal(.8, .05), rng.normal(900, 150)]
    elif kind == "off_hours_insider":
        v = [rng.normal(90, 12), rng.normal(.05, .02), rng.normal(2, .7), rng.normal(3, 1), rng.normal(.95, .03), rng.normal(45, 8)]
    else:
        raise ValueError(f"unknown log kind: {kind}")
    return np.clip(np.asarray(v, dtype=np.float64), 0, None)


class LogAnomalyDetector:
    engine = "isolation-forest"

    def __init__(self, seed: int = 13, baseline_windows: int = 1000) -> None:
        rng = np.random.default_rng(seed)
        x = np.stack([make_log_window("benign", rng) for _ in range(baseline_windows)])
        self.mean, self.std = x.mean(axis=0), x.std(axis=0) + 1e-6
        self.model = IsolationForest(n_estimators=150, random_state=seed).fit(x)
        self.baseline_scores = self.model.score_samples(x)

    def analyze(self, window) -> dict:
        w = np.asarray(window, dtype=np.float64)
        if w.shape != (len(FEATURES),) or not np.isfinite(w).all():
            raise ValueError(f"log window must be {len(FEATURES)} finite numbers: {', '.join(FEATURES)}")
        score = float(self.model.score_samples(w[None])[0])
        rarity = float((self.baseline_scores > score).mean())          # share of benign windows that look more normal
        prob = float(np.clip((rarity - 0.98) / 0.02, 0, 1))            # rarer than 98% of the benign baseline before it counts
        z = (w - self.mean) / self.std
        order = np.argsort(-np.abs(z))[:3]
        drivers = [{"feature": FEATURES[i], "value": round(float(w[i]), 2), "z_score": round(float(z[i]), 1)} for i in order]
        zf = dict(zip(FEATURES, z))
        if prob == 0:
            label = "normal"
        elif zf["failed_ratio"] > 4:
            label = "credential_attack"
        elif zf["mb_out"] > 4:
            label = "data_exfiltration"
        elif zf["off_hours_ratio"] > 4:
            label = "off_hours_activity"
        else:
            label = "anomalous_activity"
        return {"engine": self.engine, "label": label, "confidence": round(max(prob, 1 - prob), 4),
                "anomaly_probability": round(prob, 4), "rarity_percentile": round(rarity, 4), "drivers": drivers,
                "window": {f: round(float(v), 3) for f, v in zip(FEATURES, w)}}
