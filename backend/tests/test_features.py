import json
import time

import numpy as np
import pytest

from app.agent.intel import ThreatIntel
from app.agent.memory import CaseMemory
from app.agent.orchestrator import KILL_CHAIN, Investigator
from app.cnn.inference import Detector
from app.config import DATA_DIR, Settings
from app.db import Database
from app.ml.log_anomaly import LOG_KINDS, LogAnomalyDetector, make_log_window
from app.observability import Metrics, RateLimiter
from app.rag.retriever import KnowledgeBase
from app.reporting import to_markdown
from app.streaming import stream_investigation


@pytest.fixture(scope="module")
def parts():
    return KnowledgeBase(), Detector("none"), ThreatIntel(), LogAnomalyDetector()


def make_inv(parts, memory=None):
    kb, det, intel, logs = parts
    return Investigator(kb, det, intel, Settings(anthropic_api_key=""), logs, memory)


def alerts():
    return {a["id"]: a for a in json.loads((DATA_DIR / "demo_alerts.json").read_text())}


# --------------------------------------------------------- log anomaly (ML)
def test_log_detector_flags_attacks_and_passes_benign(parts):
    det, rng = parts[3], np.random.default_rng(21)
    assert sum(det.analyze(make_log_window("benign", rng))["label"] == "normal" for _ in range(100)) >= 94
    expect = {"credential_stuffing": "credential_attack", "data_exfil": "data_exfiltration", "off_hours_insider": "off_hours_activity"}
    for kind, label in expect.items():
        assert sum(det.analyze(make_log_window(kind, rng))["label"] == label for _ in range(50)) >= 45


def test_log_window_validation(parts):
    with pytest.raises(ValueError):
        parts[3].analyze([1, 2, 3])
    with pytest.raises(ValueError):
        parts[3].analyze([float("nan")] * 6)


# ---------------------------------------------------------------- agent
def test_exfil_alert_uses_log_model_and_scores_high(parts):
    r = make_inv(parts).investigate(alerts()["ALERT-1048"])
    assert "analyze_logs" in [s["tool"] for s in r["steps"]]
    assert r["evidence"]["log_anomaly"]["label"] == "data_exfiltration"
    assert r["report"]["risk_score"] >= 60
    assert "T1041" in [m["id"] for m in r["report"]["mitre"]] or "T1567" in [m["id"] for m in r["report"]["mitre"]]


def test_credential_stuffing_maps_to_brute_force(parts):
    r = make_inv(parts).investigate(alerts()["ALERT-1049"])
    assert "T1110" in [m["id"] for m in r["report"]["mitre"]]


def test_kill_chain_structure(parts):
    r = make_inv(parts).investigate(alerts()["ALERT-1042"])
    kc = r["report"]["kill_chain"]
    assert [k["tactic"] for k in kc] == KILL_CHAIN
    assert any(k["hit"] for k in kc) and any(k["tactic"] == "Impact" and k["hit"] for k in kc)


def test_cache_dedupes_identical_alerts(parts):
    inv = make_inv(parts)
    a = alerts()["ALERT-1043"]
    first, second = inv.investigate(a), inv.investigate(a)
    assert first["cached"] is False and second["cached"] is True and inv.cache_hits == 1
    assert first["report"]["risk_score"] == second["report"]["risk_score"]
    second["steps"].clear()                       # mutating a returned copy must not corrupt the cache
    assert len(inv.investigate(a)["steps"]) > 0


def test_on_step_callback_receives_every_step(parts):
    seen = []
    r = make_inv(parts).investigate(alerts()["ALERT-1044"], on_step=seen.append)
    assert [s["n"] for s in seen] == [s["n"] for s in r["steps"]]


# ---------------------------------------------------------------- memory
def test_case_memory_recalls_similar_cases(parts):
    db = Database(":memory:")
    inv = make_inv(parts)
    first = inv.investigate(alerts()["ALERT-1042"])
    db.save_case(alerts()["ALERT-1042"], first, "bob")
    memory = CaseMemory(db.case_corpus)
    hits = memory.find("Invoice attachment spawned encoded PowerShell ransomware-like file")
    assert hits and hits[0]["alert_id"] == "ALERT-1042"
    assert memory.find("quarterly cafeteria menu planning") == []
    inv2 = make_inv(parts, memory)
    r = inv2.investigate(alerts()["ALERT-1042"])
    assert r["report"]["similar_cases"] and "recall_similar_cases" in [s["tool"] for s in r["steps"]]


def test_empty_memory_is_safe(parts):
    assert CaseMemory(lambda: []).find("anything") == []


# ---------------------------------------------------------------- reporting
def test_markdown_report(parts):
    r = make_inv(parts).investigate(alerts()["ALERT-1042"])
    r["case_id"], r["created"] = 7, time.time()
    md = to_markdown(r)
    assert md.startswith("# Incident report:") and "## Proposed response" in md and "Case:** 7" in md
    assert "- [ ]" in md and "| 1 | `search_knowledge`" in md


# ---------------------------------------------------------------- streaming
def test_stream_emits_steps_then_result(parts):
    inv = make_inv(parts)
    frames = list(stream_investigation(lambda a, cb: inv.investigate(a, on_step=cb), alerts()["ALERT-1045"]))
    kinds = [f.split("\n")[0] for f in frames]
    assert kinds[-1] == "event: result" and kinds.count("event: step") >= 5


def test_stream_reports_errors():
    def boom(a, cb):
        raise RuntimeError("kaput")
    frames = list(stream_investigation(boom, {}))
    assert frames[0].startswith("event: error") and "kaput" in frames[0]


# ---------------------------------------------------------------- ops
def test_rate_limiter_bucket_and_refill():
    rl = RateLimiter(60)                            # 1 token per second, burst 60
    assert all(rl.allow("a", now=0.0)[0] for _ in range(60))
    ok, retry = rl.allow("a", now=0.0)
    assert not ok and retry >= 1
    assert rl.allow("a", now=2.0)[0]                # refilled
    assert rl.allow("b", now=0.0)[0]                # other clients unaffected


def test_metrics_render():
    m = Metrics()
    m.observe("GET", "/api/health", 200, 0.01)
    m.inc("investigations_total")
    text = m.render()
    assert 'aegis_http_requests_total{method="GET",route="/api/health",status="200"} 1' in text
    assert "aegis_investigations_total 1" in text
