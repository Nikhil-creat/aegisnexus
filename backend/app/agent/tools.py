"""Tools the agent can call. All are read-only: the agent can investigate and
recommend, but it can never contain, delete, block or execute anything."""
from __future__ import annotations

import base64
import binascii
import hashlib
import zlib
from dataclasses import dataclass, field

import numpy as np

from ..cnn.inference import Detector
from ..cnn.synthetic import make_file, make_flow
from ..ml.log_anomaly import LogAnomalyDetector, make_log_window
from ..rag.retriever import KnowledgeBase
from .intel import ThreatIntel
from .memory import CaseMemory

TOOL_SPECS = [
    {"name": "search_knowledge",
     "description": "Search the security knowledge base (MITRE ATT&CK, OWASP, incident-response playbooks). Returns ranked passages with IDs.",
     "input_schema": {"type": "object", "properties": {"query": {"type": "string"}, "k": {"type": "integer", "minimum": 1, "maximum": 8}}, "required": ["query"]}},
    {"name": "classify_artifact",
     "description": "Render the alert's attached file as a byte-plot image and classify it with the CNN. Read-only; the file is never executed.",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "classify_flow",
     "description": "Classify the alert's network-flow window (16 packets x 5 features) with the 1-D CNN.",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "analyze_logs",
     "description": "Score the alert's activity window (event rate, failed ratio, users, IPs, off-hours share, MB out) with an Isolation Forest anomaly model.",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "recall_similar_cases",
     "description": "Find similar past investigations from case history (agent memory).",
     "input_schema": {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]}},
    {"name": "check_indicators",
     "description": "Look up the alert's IPs, domains and file hashes in threat intelligence.",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "map_to_mitre",
     "description": "Map observed behaviour to MITRE ATT&CK techniques using retrieval. Classifier findings are added automatically.",
     "input_schema": {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]}},
    {"name": "compute_risk",
     "description": "Combine all evidence into a 0-100 risk score, severity and verdict (deterministic).",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "recommend_response",
     "description": "Retrieve playbook steps and mitigations. Returns PROPOSED actions that require human approval.",
     "input_schema": {"type": "object", "properties": {}}},
]

LABEL_HINTS = {
    "ransomware_like": "ransomware encrypted files ransom note high entropy",
    "packed_or_encrypted": "packed obfuscated packer temp directory executable",
    "trojan_dropper": "dropper download payload second stage",
    "syn_flood": "syn flood half-open connections denial of service",
    "port_scan": "port scan sequential ports reconnaissance service discovery",
    "brute_force": "brute force password guessing failed login ssh",
    "credential_attack": "brute force password guessing failed login credential stuffing",
    "data_exfiltration": "exfiltration large outbound upload data theft",
    "off_hours_activity": "valid accounts compromised account off-hours",
}
LABEL_NAMES = {
    "benign": "benign", "packed_or_encrypted": "packed or encrypted binary", "trojan_dropper": "trojan dropper",
    "ransomware_like": "ransomware-like", "syn_flood": "SYN flood", "port_scan": "port scan", "brute_force": "brute force",
    "normal": "normal", "credential_attack": "credential attack", "data_exfiltration": "data exfiltration",
    "off_hours_activity": "off-hours activity", "anomalous_activity": "anomalous activity",
}
_HINT_WEIGHT = {"low": 0.1, "medium": 0.4, "high": 0.7, "critical": 1.0}


@dataclass
class Case:
    """Working state for one investigation."""
    alert: dict
    max_upload_bytes: int
    file_bytes: bytes | None = None
    flow: np.ndarray | None = None
    logs: np.ndarray | None = None
    findings: dict = field(default_factory=dict)
    evidence: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        a = self.alert
        seed = zlib.crc32(str(a.get("id", "")).encode())
        if a.get("file_b64"):
            try:
                data = base64.b64decode(a["file_b64"], validate=True)
            except (binascii.Error, ValueError) as exc:
                raise ValueError("file_b64 is not valid base64") from exc
            if len(data) > self.max_upload_bytes:
                raise ValueError("attached file exceeds the size limit")
            self.file_bytes = data
        elif a.get("synthetic_file"):
            self.file_bytes = make_file(a["synthetic_file"], np.random.default_rng(seed))
        if a.get("flow"):
            self.flow = np.asarray(a["flow"], dtype=np.float32)
        elif a.get("synthetic_flow"):
            self.flow = make_flow(a["synthetic_flow"], np.random.default_rng(seed + 1))
        if a.get("logs"):
            self.logs = np.asarray(a["logs"], dtype=np.float64)
        elif a.get("synthetic_logs"):
            self.logs = make_log_window(a["synthetic_logs"], np.random.default_rng(seed + 2))

    @property
    def has_file(self) -> bool:
        return self.file_bytes is not None

    @property
    def has_flow(self) -> bool:
        return self.flow is not None

    @property
    def has_logs(self) -> bool:
        return self.logs is not None

    @property
    def has_indicators(self) -> bool:
        ind = self.alert.get("indicators") or {}
        return bool(ind.get("ips") or ind.get("domains") or ind.get("hashes") or self.has_file)

    def cite(self, hits: list[dict]) -> None:
        seen = self.findings.setdefault("citations", [])
        known = {c["id"] for c in seen}
        for h in hits:
            if h["id"] not in known:
                seen.append({"id": h["id"], "title": h["title"], "source": h["source"]})
                known.add(h["id"])


class ToolBox:
    def __init__(self, kb: KnowledgeBase, detector: Detector, intel: ThreatIntel, case: Case,
                 log_detector: LogAnomalyDetector | None = None, memory: CaseMemory | None = None) -> None:
        self.kb, self.detector, self.intel, self.case = kb, detector, intel, case
        self.log_detector, self.memory = log_detector, memory
        self._tools = {
            "search_knowledge": self.search_knowledge,
            "classify_artifact": self.classify_artifact,
            "classify_flow": self.classify_flow,
            "analyze_logs": self.analyze_logs,
            "recall_similar_cases": self.recall_similar_cases,
            "check_indicators": self.check_indicators,
            "map_to_mitre": self.map_to_mitre,
            "compute_risk": self.compute_risk,
            "recommend_response": self.recommend_response,
        }

    def call(self, name: str, args: dict | None) -> dict:
        fn = self._tools.get(name)
        if fn is None:
            return {"error": f"unknown tool '{name}'", "summary": "Unknown tool"}
        try:
            return fn(**(args or {}))
        except TypeError as exc:
            return {"error": f"bad arguments: {exc}", "summary": "Bad arguments"}
        except Exception as exc:  # tool failures must never crash the agent loop
            return {"error": str(exc)[:300], "summary": f"Tool failed: {str(exc)[:120]}"}

    # ---------------------------------------------------------------- RAG --
    def search_knowledge(self, query: str, k: int = 4) -> dict:
        hits = self.kb.search(str(query), k=max(1, min(int(k), 8)))
        self.case.cite(hits)
        return {"summary": f"{len(hits)} passages: " + ", ".join(h["id"] for h in hits),
                "hits": [{"id": h["id"], "title": h["title"], "score": h["score"]} for h in hits]}

    # ---------------------------------------------------------------- CNN --
    def classify_artifact(self) -> dict:
        if not self.case.has_file:
            return {"available": False, "summary": "No file attached to this alert"}
        res = self.detector.analyze_file(self.case.file_bytes)
        self.case.evidence["byteplot"] = res.pop("byteplot")
        self.case.evidence["attention"] = res.pop("attention")
        self.case.findings["file"] = res
        return {**res, "summary": f"{LABEL_NAMES[res['label']]} at {res['confidence'] * 100:.0f}% confidence, "
                                  f"entropy {res['entropy_bits_per_byte']} bits/byte ({res['engine']})"}

    def classify_flow(self) -> dict:
        if not self.case.has_flow:
            return {"available": False, "summary": "No network flow attached to this alert"}
        res = self.detector.analyze_flow(self.case.flow)
        self.case.findings["flow"] = res
        return {**res, "summary": f"{LABEL_NAMES[res['label']]} at {res['confidence'] * 100:.0f}% confidence ({res['engine']})"}

    # --------------------------------------------------- anomaly + memory --
    def analyze_logs(self) -> dict:
        if not self.case.has_logs or self.log_detector is None:
            return {"available": False, "summary": "No activity window attached to this alert"}
        res = self.log_detector.analyze(self.case.logs)
        self.case.findings["logs"] = res
        top = res["drivers"][0]
        return {**res, "summary": f"{LABEL_NAMES[res['label']]}, anomaly {res['anomaly_probability'] * 100:.0f}%, "
                                  f"top driver {top['feature']} (z={top['z_score']})"}

    def recall_similar_cases(self, text: str) -> dict:
        if self.memory is None:
            return {"available": False, "summary": "No case history available"}
        hits = self.memory.find(str(text), k=3)
        self.case.findings["similar_cases"] = hits
        return {"similar": hits, "summary": (f"{len(hits)} similar past case(s): " + ", ".join(
            f"#{h['case_id']} {h['severity']} ({h['similarity']})" for h in hits)) if hits else "No similar past cases"}

    # -------------------------------------------------------------- intel --
    def check_indicators(self) -> dict:
        ind = self.case.alert.get("indicators") or {}
        hashes = list(ind.get("hashes") or [])
        if self.case.has_file:
            hashes += [hashlib.sha256(self.case.file_bytes).hexdigest(),
                       hashlib.md5(self.case.file_bytes, usedforsecurity=False).hexdigest()]
        res = self.intel.lookup(ind.get("ips") or [], ind.get("domains") or [], hashes)
        self.case.findings["intel"] = res
        tags = ", ".join(f"{h['value']} ({h['tag']})" for h in res["hits"]) or "no matches"
        return {**res, "summary": f"{len(res['hits'])} hit(s) of {res['checked']} indicators: {tags}"}

    # ------------------------------------------------------------- MITRE --
    def map_to_mitre(self, text: str) -> dict:
        hints = []
        for key in ("file", "flow", "logs"):
            f = self.case.findings.get(key)
            if f and f["label"] in LABEL_HINTS and f["confidence"] >= 0.5:
                hints.append(LABEL_HINTS[f["label"]])
        hits = self.kb.search(f"{text} {' '.join(hints)}", k=5, source="MITRE ATT&CK",
                              min_score=0.08 if hints else 0.25)
        if hits:  # drop the weak tail: keep techniques scoring at least 45% of the best match
            hits = [h for h in hits if h["score"] >= 0.45 * hits[0]["score"]][:4]
        self.case.cite(hits)
        self.case.findings["mitre"] = [
            {"id": h["id"], "name": h["title"], "tactic": h["tactic"], "score": h["score"]} for h in hits]
        return {"summary": ", ".join(f"{h['id']} {h['tactic']}" for h in hits) or "no confident mapping",
                "techniques": self.case.findings["mitre"]}

    # -------------------------------------------------------------- risk --
    def compute_risk(self) -> dict:
        f = self.case.findings
        parts: list[tuple[str, float, float]] = []  # (name, weight, value 0..1)
        if "intel" in f:
            conf = max((h["confidence"] for h in f["intel"]["hits"]), default=0)
            parts.append(("threat_intel", 0.35, conf / 100.0))
        if "file" in f:
            parts.append(("file_cnn", 0.35, f["file"]["malicious_probability"]))
        if "flow" in f:
            parts.append(("flow_cnn", 0.35, f["flow"]["anomaly_probability"]))
        if "logs" in f:
            parts.append(("log_anomaly", 0.35, f["logs"]["anomaly_probability"]))
        parts.append(("alert_severity", 0.15, _HINT_WEIGHT.get(self.case.alert.get("severity_hint", "medium"), 0.4)))
        tactics = {m["tactic"] for m in f.get("mitre", [])}
        parts.append(("attack_coverage", 0.10, min(1.0, len(tactics) / 3)))
        score = round(100 * sum(w * v for _, w, v in parts) / sum(w for _, w, _ in parts))
        severity = "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 35 else "low"
        verdict = ("likely malicious - escalate" if score >= 80 else "suspicious - investigate now" if score >= 60
                   else "needs analyst review" if score >= 35 else "likely benign - monitor")
        f["risk"] = {"score": score, "severity": severity, "verdict": verdict,
                     "components": [{"name": n, "weight": w, "value": round(v, 3)} for n, w, v in parts]}
        return {**f["risk"], "summary": f"risk {score}/100 ({severity}): {verdict}"}

    # ---------------------------------------------------------- response --
    def recommend_response(self) -> dict:
        f = self.case.findings
        if "risk" not in f:
            self.compute_risk()
        if f["risk"]["score"] < 30:
            actions = [{"action": "Close as a benign true-negative and record the baseline", "rationale":
                        "All evidence sources scored low", "source": "risk-model", "status": "proposed"},
                       {"action": "Tune the detection threshold that raised this alert", "rationale":
                        "Reduce analyst fatigue from repeat false positives", "source": "risk-model", "status": "proposed"}]
        else:
            a = self.case.alert
            hints = " ".join(LABEL_HINTS.get(f.get(k, {}).get("label", ""), "") for k in ("file", "flow", "logs"))
            query = f"{a.get('title', '')} {a.get('description', '')} {hints}"
            books = self.kb.search(query, k=2, source="IR Playbook", min_score=0.05)
            self.case.cite(books)
            actions = []
            for rank, pb in enumerate(books):
                for step in pb["steps"][: 3 if rank == 0 else 1]:
                    actions.append({"action": step, "rationale": pb["title"], "source": pb["id"], "status": "pending_approval"})
            for tech in f.get("mitre", [])[:3]:
                doc = self.kb.get(tech["id"])
                if doc and doc.get("mitigations"):
                    actions.append({"action": doc["mitigations"][0], "rationale": f"Mitigates {doc['id']} {doc['title']}",
                                    "source": doc["id"], "status": "pending_approval"})
        unique: list[dict] = []
        for act in actions:  # drop near-duplicates (a mitigation that restates a playbook step)
            low = act["action"].lower()
            if not any(low[:16] in u["action"].lower() or u["action"].lower()[:16] in low for u in unique):
                unique.append(act)
        f["recommendations"] = unique
        return {"summary": f"{len(unique)} proposed action(s), none executed (human approval required)",
                "actions": unique}
