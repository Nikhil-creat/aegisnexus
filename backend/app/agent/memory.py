"""Agent memory: retrieve similar past cases (TF-IDF over saved case summaries)."""
from __future__ import annotations

import threading
from typing import Callable

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import linear_kernel


class CaseMemory:
    def __init__(self, corpus_fn: Callable[[], list[dict]]) -> None:
        self._fn = corpus_fn
        self._lock = threading.Lock()
        self._sig = None
        self._rows: list[dict] = []
        self._vec = None
        self._matrix = None

    def _refresh(self) -> None:
        rows = self._fn()
        sig = (len(rows), rows[0]["id"] if rows else None)
        if sig == self._sig:
            return
        self._sig, self._rows, self._vec, self._matrix = sig, rows, None, None
        if rows:
            try:
                self._vec = TfidfVectorizer(stop_words="english", ngram_range=(1, 2), sublinear_tf=True)
                self._matrix = self._vec.fit_transform([f"{r['title']}. {r['facts'] or ''}" for r in rows])
            except ValueError:  # empty vocabulary
                self._vec = self._matrix = None

    def find(self, text: str, k: int = 3, min_score: float = 0.25, exclude_case: int | None = None) -> list[dict]:
        with self._lock:
            self._refresh()
            if self._vec is None or not text.strip():
                return []
            sims = linear_kernel(self._vec.transform([text[:2000]]), self._matrix).ravel()
            out = []
            for i in sims.argsort()[::-1]:
                r = self._rows[i]
                if sims[i] < min_score:
                    break
                if r["id"] == exclude_case:
                    continue
                out.append({"case_id": r["id"], "alert_id": r["alert_id"], "title": r["title"], "severity": r["severity"],
                            "risk": r["risk"], "verdict": r["verdict"], "similarity": round(float(sims[i]), 3)})
                if len(out) >= k:
                    break
            return out
