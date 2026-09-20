from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

MAX_B64 = 7_000_000  # ~5 MB of raw bytes


class SearchRequest(BaseModel):
    query: str = Field(min_length=2, max_length=500)
    k: int = Field(default=4, ge=1, le=8)


class FlowRequest(BaseModel):
    sequence: list[list[float]] = Field(description="16 packets x 5 features: size, direction, iat, flag, port")


class Indicators(BaseModel):
    ips: list[str] = Field(default_factory=list, max_length=50)
    domains: list[str] = Field(default_factory=list, max_length=50)
    hashes: list[str] = Field(default_factory=list, max_length=50)


class Alert(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str = Field(default="ALERT-0000", max_length=64)
    title: str = Field(min_length=3, max_length=200)
    description: str = Field(default="", max_length=4000)
    source: str = Field(default="manual", max_length=64)
    severity_hint: Literal["low", "medium", "high", "critical"] = "medium"
    indicators: Indicators = Field(default_factory=Indicators)
    file_b64: Optional[str] = Field(default=None, max_length=MAX_B64)
    flow: Optional[list[list[float]]] = None
    # demo helpers: generate harmless synthetic artifacts server-side
    synthetic_file: Optional[Literal["benign", "packed_or_encrypted", "trojan_dropper", "ransomware_like"]] = None
    logs: Optional[list[float]] = Field(default=None, min_length=6, max_length=6)
    synthetic_logs: Optional[Literal["benign", "credential_stuffing", "data_exfil", "off_hours_insider"]] = None
    synthetic_flow: Optional[Literal["benign", "syn_flood", "port_scan", "brute_force"]] = None
