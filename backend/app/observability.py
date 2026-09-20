"""Prometheus-style metrics and a token-bucket rate limiter (standard library only)."""
from __future__ import annotations

import threading
import time
from collections import defaultdict


class Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.requests: dict[tuple[str, str, int], int] = defaultdict(int)
        self.latency_sum: dict[str, float] = defaultdict(float)
        self.latency_count: dict[str, int] = defaultdict(int)
        self.counters: dict[str, int] = defaultdict(int)

    def observe(self, method: str, route: str, status: int, seconds: float) -> None:
        with self._lock:
            self.requests[(method, route, status)] += 1
            self.latency_sum[route] += seconds
            self.latency_count[route] += 1

    def inc(self, name: str, n: int = 1) -> None:
        with self._lock:
            self.counters[name] += n

    def render(self) -> str:
        with self._lock:
            lines = ["# TYPE aegis_http_requests_total counter"]
            for (m, r, s), n in sorted(self.requests.items()):
                lines.append(f'aegis_http_requests_total{{method="{m}",route="{r}",status="{s}"}} {n}')
            lines.append("# TYPE aegis_http_request_seconds summary")
            for r in sorted(self.latency_sum):
                lines.append(f'aegis_http_request_seconds_sum{{route="{r}"}} {self.latency_sum[r]:.6f}')
                lines.append(f'aegis_http_request_seconds_count{{route="{r}"}} {self.latency_count[r]}')
            for name, n in sorted(self.counters.items()):
                lines.append(f"# TYPE aegis_{name} counter\naegis_{name} {n}")
        return "\n".join(lines) + "\n"


class RateLimiter:
    """Token bucket per key: `per_minute` sustained rate with a burst equal to the same number."""

    def __init__(self, per_minute: int) -> None:
        self.capacity = float(per_minute)
        self.rate = per_minute / 60.0
        self._state: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, now: float | None = None) -> tuple[bool, int]:
        now = time.monotonic() if now is None else now
        with self._lock:
            tokens, last = self._state.get(key, (self.capacity, now))
            tokens = min(self.capacity, tokens + (now - last) * self.rate)
            if tokens >= 1:
                self._state[key] = (tokens - 1, now)
                if len(self._state) > 10_000:  # bound memory under address-spoofing floods
                    self._state.pop(next(iter(self._state)))
                return True, 0
            self._state[key] = (tokens, now)
            return False, max(1, int((1 - tokens) / self.rate) + 1)
