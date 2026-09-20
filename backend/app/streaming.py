"""Server-Sent Events helper: stream agent steps to the browser as they happen."""
from __future__ import annotations

import json
import queue
import threading
from typing import Callable, Iterator


def sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n"


def stream_investigation(run: Callable[[dict, Callable[[dict], None]], dict], alert: dict) -> Iterator[str]:
    """`run(alert, on_step)` executes the investigation; yields SSE frames: step*, then result or error."""
    q: queue.Queue = queue.Queue()
    done = object()

    def worker() -> None:
        try:
            q.put(("result", run(alert, lambda step: q.put(("step", step)))))
        except Exception as exc:  # surface any failure to the client instead of hanging the stream
            q.put(("error", {"detail": str(exc)[:300]}))
        finally:
            q.put((done, None))

    threading.Thread(target=worker, daemon=True).start()
    while True:
        kind, payload = q.get()
        if kind is done:
            return
        yield sse(kind, payload)
