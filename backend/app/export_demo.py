"""Export recorded investigations + the knowledge base for the static GitHub Pages demo.

    cd backend && python -m app.export_demo --out ../docs/data
"""
from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path

from .agent.intel import ThreatIntel
from .agent.orchestrator import Investigator
from .cnn.inference import Detector
from .config import DATA_DIR, get_settings
from .rag.retriever import KnowledgeBase


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="../docs/data")
    ap.add_argument("--models", default=os.getenv("MODEL_DIR", "models"))
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    kb, detector = KnowledgeBase(), Detector(args.models)
    investigator = Investigator(kb, detector, ThreatIntel(), get_settings())
    alerts = json.loads((DATA_DIR / "demo_alerts.json").read_text(encoding="utf-8"))
    runs = [{"alert": a, "result": investigator.investigate(a)} for a in alerts]

    (out / "investigations.json").write_text(json.dumps({
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime()),
        "llm": investigator.llm_name, "cnn_file": detector.file_engine, "cnn_flow": detector.flow_engine,
        "runs": runs}, separators=(",", ":")))
    (out / "kb.json").write_text(json.dumps(kb.docs, separators=(",", ":")))
    metrics = detector.metrics or {"available": False}
    (out / "metrics.json").write_text(json.dumps(metrics, indent=1))
    print(f"exported {len(runs)} investigations, {len(kb)} knowledge docs -> {out.resolve()} "
          f"(file engine: {detector.file_engine}, flow engine: {detector.flow_engine})")


if __name__ == "__main__":
    main()
