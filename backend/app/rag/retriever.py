"""Retrieval-Augmented Generation (RAG) knowledge layer.

A small, curated corpus (MITRE ATT&CK techniques, OWASP Top 10, incident-response
playbooks) is indexed with TF-IDF (uni+bi-grams, sublinear tf). Retrieval is fully
local: no API key, no network, deterministic - which makes it testable and cheap.
Swap `KnowledgeBase._embed` for a sentence-embedding model or a vector DB
(Chroma, pgvector, Qdrant) without touching the agent code.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import linear_kernel

from ..config import DATA_DIR

_TID = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)


class KnowledgeBase:
    def __init__(self, path: Path | str | None = None) -> None:
        path = Path(path) if path else DATA_DIR / "knowledge_base.json"
        self.docs: list[dict] = json.loads(path.read_text(encoding="utf-8"))
        self._by_id = {d["id"]: d for d in self.docs}
        self._vec = TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, stop_words="english")
        self._matrix = self._vec.fit_transform([self._doc_text(d) for d in self.docs])

    @staticmethod
    def _doc_text(d: dict) -> str:
        kw = " ".join(d.get("keywords", []))
        return f"{d['title']}. {d['tactic']}. {kw}. {kw}. {d['text']}"

    def __len__(self) -> int:
        return len(self.docs)

    def get(self, doc_id: str) -> dict | None:
        return self._by_id.get(doc_id)

    def search(self, query: str, k: int = 4, source: str | None = None, min_score: float = 0.04) -> list[dict]:
        query = (query or "").strip()[:2000]
        if not query:
            return []
        sims = linear_kernel(self._vec.transform([query]), self._matrix).ravel()
        for tid in _TID.findall(query):  # an explicit technique ID is a strong signal
            doc = self._by_id.get(tid.upper())
            if doc is not None:
                sims[self.docs.index(doc)] = max(sims[self.docs.index(doc)], 1.0)
        hits: list[dict] = []
        for i in np.argsort(-sims):
            if sims[i] < min_score:
                break
            doc = self.docs[i]
            if source and doc["source"] != source:
                continue
            hits.append(self._hit(doc, float(sims[i])))
            if len(hits) >= k:
                break
        return hits

    @staticmethod
    def _hit(doc: dict, score: float) -> dict:
        return {
            "id": doc["id"],
            "title": doc["title"],
            "source": doc["source"],
            "tactic": doc["tactic"],
            "score": round(score, 3),
            "snippet": doc["text"],
            "mitigations": doc.get("mitigations", []),
            "steps": doc.get("steps", []),
        }
