"""
A tiny async pub/sub bus so a run can emit progress without knowing who listens.

Consumers: the CLI (renders via the design system), the API (WebSocket), and the
MCP server (progress notifications). All optional — passing no bus runs silent.
"""

import asyncio
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Dict, Optional


@dataclass
class Event:
    kind: str                     # run_started | step_started | step_progress | finding | run_completed | run_failed
    target: str = ""
    module: str = ""
    message: str = ""
    pct: Optional[float] = None
    data: Dict[str, Any] = field(default_factory=dict)


class EventBus:
    """Fan-out bus. Publishers call publish(); consumers iterate subscribe()."""

    def __init__(self) -> None:
        self._queues: list[asyncio.Queue] = []
        self._closed = False

    def publish(self, event: Event) -> None:
        for q in list(self._queues):
            q.put_nowait(event)

    async def subscribe(self) -> AsyncIterator[Event]:
        q: asyncio.Queue = asyncio.Queue()
        self._queues.append(q)
        if self._closed:
            # Subscribed after close() — don't hang; terminate immediately.
            q.put_nowait(None)
        try:
            # Drain until the None sentinel so queued events aren't dropped when
            # the bus is closed right after a burst of publishes.
            while True:
                event = await q.get()
                if event is None:  # sentinel
                    break
                yield event
        finally:
            if q in self._queues:
                self._queues.remove(q)

    def close(self) -> None:
        self._closed = True
        for q in list(self._queues):
            q.put_nowait(None)
