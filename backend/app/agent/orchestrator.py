"""The agent loop: plan -> call tools -> observe -> report.

Guardrails:
  * tools are read-only; response actions are only ever *proposed*;
  * risk score, severity and MITRE mapping come from deterministic tools, never
    from free-form LLM text;
  * alert content is treated as untrusted data in the LLM prompt;
  * if the LLM is unavailable or fails, the offline planner takes over.

Performance: identical alerts inside a short window reuse the previous analysis
(alert de-duplication), which also saves LLM cost during alert storms.
"""
from __future__ import annotations

import copy
import hashlib
import json
import threading
import time
from collections import OrderedDict
from typing import Callable

from ..cnn.inference import Detector
from ..config import Settings, get_settings
from ..ml.log_anomaly import LogAnomalyDetector
from ..rag.retriever import KnowledgeBase
from .intel import ThreatIntel
from .memory import CaseMemory
from .tools import LABEL_NAMES, Case, ToolBox

REQUIRED = ("map_to_mitre", "compute_risk", "recommend_response")
KILL_CHAIN = ["Initial Access", "Execution", "Persistence", "Defense Evasion", "Credential Access", "Discovery",
              "Lateral Movement", "Command and Control", "Exfiltration", "Impact"]
CACHE_SIZE, CACHE_TTL = 128, 600


class Investigator:
    def __init__(self, kb: KnowledgeBase, detector: Detector, intel: ThreatIntel, settings: Settings | None = None,
                 log_detector: LogAnomalyDetector | None = None, memory: CaseMemory | None = None) -> None:
        self.kb, self.detector, self.intel = kb, detector, intel
        self.settings = settings or get_settings()
        self.log_detector = log_detector or LogAnomalyDetector()
        self.memory = memory
        self.planner = None
        self.llm_error: str | None = None
        self.cache_hits = 0
        self._cache: OrderedDict[str, tuple[float, dict]] = OrderedDict()
        self._cache_lock = threading.Lock()
        if self.settings.anthropic_api_key:
            try:
                from .llm import ClaudePlanner
                self.planner = ClaudePlanner(self.settings.anthropic_api_key, self.settings.llm_model,
                                             self.settings.max_agent_steps)
            except Exception as exc:  # missing SDK etc. -> stay offline
                self.llm_error = f"{type(exc).__name__}: {exc}"

    @property
    def llm_name(self) -> str:
        return self.settings.llm_model if self.planner else "offline-planner"

    # ---------------------------------------------------------------- cache --
    def _key(self, alert: dict) -> str:
        raw = json.dumps(alert, sort_keys=True, default=str) + self.llm_name
        return hashlib.sha256(raw.encode()).hexdigest()

    def _cache_get(self, key: str) -> dict | None:
        with self._cache_lock:
            hit = self._cache.get(key)
            if hit and time.time() - hit[0] < CACHE_TTL:
                self._cache.move_to_end(key)
                return copy.deepcopy(hit[1])
            self._cache.pop(key, None)
        return None

    def _cache_put(self, key: str, result: dict) -> None:
        with self._cache_lock:
            self._cache[key] = (time.time(), copy.deepcopy(result))
            while len(self._cache) > CACHE_SIZE:
                self._cache.popitem(last=False)

    # ------------------------------------------------------------------ run --
    def investigate(self, alert: dict, on_step: Callable[[dict], None] | None = None) -> dict:
        key = self._key(alert)
        cached = self._cache_get(key)
        if cached is not None:
            self.cache_hits += 1
            cached["cached"] = True
            for s in cached["steps"]:
                if on_step:
                    on_step(s)
            return cached

        t_start = time.perf_counter()
        case = Case(alert=alert, max_upload_bytes=self.settings.max_upload_bytes)
        toolbox = ToolBox(self.kb, self.detector, self.intel, case, self.log_detector, self.memory)
        steps: list[dict] = []

        def execute(tool: str, args: dict, thought: str) -> dict:
            t0 = time.perf_counter()
            obs = toolbox.call(tool, args)
            step = {"n": len(steps) + 1, "thought": thought or "", "tool": tool, "input": args,
                    "observation": obs, "ms": round((time.perf_counter() - t0) * 1000, 1)}
            steps.append(step)
            if on_step:
                on_step(step)
            return obs

        narrative, llm_used = "", "offline-planner"
        if self.planner is not None:
            try:
                view = {k: alert.get(k) for k in ("id", "title", "description", "source", "severity_hint", "indicators")}
                view["has_file"], view["has_flow"], view["has_logs"] = case.has_file, case.has_flow, case.has_logs
                narrative = self.planner.investigate(view, execute)
                llm_used = self.settings.llm_model
            except Exception as exc:
                self.llm_error = f"{type(exc).__name__}: {str(exc)[:200]}"
                case.findings.clear(); case.evidence.clear(); steps.clear()
        if llm_used == "offline-planner":
            self._offline_plan(case, execute)
        else:  # make sure the deterministic core always ran
            done = {s["tool"] for s in steps}
            for present, tool in ((case.has_file, "classify_artifact"), (case.has_flow, "classify_flow"),
                                  (case.has_logs, "analyze_logs"), (case.has_indicators, "check_indicators")):
                if present and tool not in done:
                    execute(tool, {}, f"Guardrail: run {tool}.")
            for tool in REQUIRED:
                if tool not in done:
                    execute(tool, {"text": self._query(alert)} if tool == "map_to_mitre" else {},
                            f"Guardrail: run {tool} so the report is complete.")

        result = self._report(alert, case, steps, narrative, llm_used)
        result["report"]["duration_ms"] = round((time.perf_counter() - t_start) * 1000, 1)
        result["cached"] = False
        self._cache_put(key, result)
        return result

    # -------------------------------------------------------- offline plan --
    @staticmethod
    def _query(alert: dict) -> str:
        return f"{alert.get('title', '')}. {alert.get('description', '')}"

    def _offline_plan(self, case: Case, execute) -> None:
        q = self._query(case.alert)
        execute("search_knowledge", {"query": q, "k": 4}, "Retrieve background knowledge for the behaviour described in the alert.")
        if self.memory is not None:
            execute("recall_similar_cases", {"text": q}, "Check case history for similar past incidents.")
        if case.has_file:
            execute("classify_artifact", {}, "The alert carries a file. Render its bytes as an image and classify the texture with the CNN.")
        if case.has_flow:
            execute("classify_flow", {}, "The alert carries a network flow. Classify the packet sequence with the 1-D CNN.")
        if case.has_logs:
            execute("analyze_logs", {}, "The alert carries an activity window. Score how rare it is against the benign baseline.")
        if case.has_indicators:
            execute("check_indicators", {}, "Look up IPs, domains and file hashes in threat intelligence.")
        execute("map_to_mitre", {"text": q}, "Map the alert text and classifier findings to MITRE ATT&CK.")
        execute("compute_risk", {}, "Combine all evidence into one explainable risk score.")
        execute("recommend_response", {}, "Retrieve playbook steps and propose actions for a human to approve.")

    # ---------------------------------------------------------------- report --
    @staticmethod
    def _kill_chain(mitre: list[dict]) -> list[dict]:
        by_tactic: dict[str, list[str]] = {}
        for m in mitre:
            by_tactic.setdefault(m["tactic"], []).append(m["id"])
        return [{"tactic": t, "hit": t in by_tactic, "techniques": by_tactic.get(t, [])} for t in KILL_CHAIN]

    def _report(self, alert: dict, case: Case, steps: list[dict], narrative: str, llm_used: str) -> dict:
        f = case.findings
        risk = f["risk"]
        parts = []
        if "file" in f:
            parts.append(f"attached file looks like {LABEL_NAMES[f['file']['label']]} ({f['file']['confidence'] * 100:.0f}%)")
        if "flow" in f:
            parts.append(f"network flow looks like {LABEL_NAMES[f['flow']['label']]} ({f['flow']['confidence'] * 100:.0f}%)")
        if "logs" in f:
            parts.append(f"activity window looks like {LABEL_NAMES[f['logs']['label']]} ({f['logs']['anomaly_probability'] * 100:.0f}% anomalous)")
        hits = f.get("intel", {}).get("hits", [])
        if hits:
            parts.append(f"{len(hits)} threat-intel match(es)")
        similar = f.get("similar_cases", [])
        if similar:
            parts.append(f"{len(similar)} similar past case(s)")
        mitre = ", ".join(m["id"] for m in f.get("mitre", [])) or "none"
        auto = (f"{alert.get('title', 'Alert')}: " + ("; ".join(parts) or "no classifiable artifacts") +
                f". ATT&CK: {mitre}. Risk {risk['score']}/100 ({risk['severity']}) - {risk['verdict']}.")
        engines = {}
        if "file" in f:
            engines["cnn_file"] = f["file"]["engine"]
        if "flow" in f:
            engines["cnn_flow"] = f["flow"]["engine"]
        if "logs" in f:
            engines["log_anomaly"] = f["logs"]["engine"]
        return {
            "alert_id": alert.get("id"),
            "title": alert.get("title"),
            "engine": {"llm": llm_used, "classifiers": engines,
                       "llm_fallback_reason": self.llm_error if llm_used == "offline-planner" and self.settings.anthropic_api_key else None},
            "steps": steps,
            "report": {
                "summary": narrative or auto,
                "facts": auto,
                "risk_score": risk["score"], "severity": risk["severity"], "verdict": risk["verdict"],
                "risk_components": risk["components"],
                "mitre": f.get("mitre", []),
                "kill_chain": self._kill_chain(f.get("mitre", [])),
                "indicator_hits": hits,
                "similar_cases": similar,
                "recommendations": f.get("recommendations", []),
                "citations": f.get("citations", [])[:8],
            },
            "evidence": {
                "byteplot": case.evidence.get("byteplot"),
                "attention": case.evidence.get("attention"),
                "file_probabilities": f.get("file", {}).get("probabilities"),
                "flow_probabilities": f.get("flow", {}).get("probabilities"),
                "log_anomaly": ({k: f["logs"][k] for k in ("label", "anomaly_probability", "rarity_percentile", "drivers", "window")}
                                if "logs" in f else None),
            },
        }
