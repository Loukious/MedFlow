from __future__ import annotations

import time
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from threading import Lock
from typing import Any, Callable


@dataclass
class JobRecord:
    id: str
    kind: str
    status: str
    created_at: float
    updated_at: float
    result: dict[str, Any] | None = None
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class JobManager:
    def __init__(self, max_workers: int = 4) -> None:
        self.executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="medflow-api")
        self.jobs: dict[str, JobRecord] = {}
        self.lock = Lock()

    def submit(self, kind: str, fn: Callable[[], dict[str, Any]], metadata: dict[str, Any] | None = None) -> JobRecord:
        job_id = uuid.uuid4().hex
        now = time.time()
        record = JobRecord(
            id=job_id,
            kind=kind,
            status="queued",
            created_at=now,
            updated_at=now,
            metadata=metadata or {},
        )
        with self.lock:
            self.jobs[job_id] = record
        future = self.executor.submit(self._run, job_id, fn)
        future.add_done_callback(lambda _: None)
        return record

    def get(self, job_id: str) -> JobRecord | None:
        with self.lock:
            return self.jobs.get(job_id)

    def list(self, limit: int = 50) -> list[JobRecord]:
        with self.lock:
            rows = sorted(self.jobs.values(), key=lambda item: item.created_at, reverse=True)
        return rows[:limit]

    def _run(self, job_id: str, fn: Callable[[], dict[str, Any]]) -> None:
        self._update(job_id, status="running")
        try:
            result = fn()
        except Exception as exc:
            self._update(job_id, status="failed", error=f"{type(exc).__name__}: {exc}")
            return
        self._update(job_id, status="succeeded", result=result)

    def _update(
        self,
        job_id: str,
        *,
        status: str,
        result: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> None:
        with self.lock:
            record = self.jobs[job_id]
            record.status = status
            record.updated_at = time.time()
            if result is not None:
                record.result = result
            if error is not None:
                record.error = error


def job_to_dict(record: JobRecord) -> dict[str, Any]:
    return asdict(record)
