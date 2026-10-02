"""
In-process async job runner.

Scans and agent runs are started as background asyncio tasks so the HTTP request
returns immediately with a job id. Each job owns an EventBus; clients stream its
progress over the WebSocket endpoint and fetch the final result via GET /jobs/{id}.
(A durable queue — arq/Redis — is a later enhancement; this keeps v1 dependency-light.)
"""

import asyncio
import uuid
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Optional

from spaf.service import EventBus


@dataclass
class Job:
    id: str
    kind: str
    target: str
    status: str = "running"            # running | completed | failed
    result: Optional[Any] = None
    error: Optional[str] = None
    bus: EventBus = field(default_factory=EventBus)


class JobManager:
    def __init__(self) -> None:
        self._jobs: Dict[str, Job] = {}

    def get(self, job_id: str) -> Optional[Job]:
        return self._jobs.get(job_id)

    def start(self, kind: str, target: str,
              run: Callable[[EventBus], Awaitable[Any]]) -> Job:
        job = Job(id=uuid.uuid4().hex, kind=kind, target=target)
        self._jobs[job.id] = job

        async def _runner():
            try:
                job.result = await run(job.bus)
                job.status = "completed"
            except Exception as exc:  # noqa: BLE001 - surface any failure to the client
                job.status = "failed"
                job.error = str(exc)
            finally:
                job.bus.close()

        asyncio.create_task(_runner())
        return job
