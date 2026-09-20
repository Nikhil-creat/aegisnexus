"""Local threat-intelligence lookup with strict input validation."""
from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path

from ..config import DATA_DIR

_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z0-9-]{2,63}$")
_HASH = re.compile(r"^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$")


class ThreatIntel:
    def __init__(self, path: Path | str | None = None) -> None:
        path = Path(path) if path else DATA_DIR / "intel.json"
        raw = json.loads(path.read_text(encoding="utf-8"))
        self.ips = raw.get("ips", {})
        self.domains = raw.get("domains", {})
        self.hashes = raw.get("hashes", {})

    def lookup(self, ips=(), domains=(), hashes=()) -> dict:
        hits, invalid, checked = [], [], 0
        for value in list(ips)[:50]:
            try:
                norm = str(ipaddress.ip_address(str(value).strip()))
            except ValueError:
                invalid.append(str(value)[:64]); continue
            checked += 1
            if norm in self.ips:
                hits.append({"type": "ip", "value": norm, **self.ips[norm]})
        for value in list(domains)[:50]:
            norm = str(value).strip().lower().rstrip(".")
            if not _DOMAIN.match(norm):
                invalid.append(str(value)[:64]); continue
            checked += 1
            if norm in self.domains:
                hits.append({"type": "domain", "value": norm, **self.domains[norm]})
        for value in list(hashes)[:50]:
            norm = str(value).strip().lower()
            if not _HASH.match(norm):
                invalid.append(str(value)[:64]); continue
            checked += 1
            if norm in self.hashes:
                hits.append({"type": "hash", "value": norm, **self.hashes[norm]})
        return {"hits": hits, "checked": checked, "invalid": invalid}
