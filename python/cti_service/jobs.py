"""In-memory job manager for the first service slice."""

from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import Event, Lock
from typing import Any

from .schemas import CreateScanRequest
from .worker import run_scan_job


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True)
class ScanJobRecord:
    job_id: str
    request: CreateScanRequest
    status: str = "queued"
    created_at: str = field(default_factory=utc_now)
    started_at: str | None = None
    finished_at: str | None = None
    error_message: str | None = None
    projection: dict[str, Any] | None = None
    cancel_requested_at: str | None = None

    def summary(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "scan_id": self.request.scan_id,
            "status": self.status,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "error_message": self.error_message,
            "result_count": len((self.projection or {}).get("results", [])),
            "event_count": len((self.projection or {}).get("events", [])),
            "log_count": len((self.projection or {}).get("logs", [])),
            "cancel_requested_at": self.cancel_requested_at,
        }


class JobManager:
    def __init__(self, max_workers: int = 4) -> None:
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="cti-engine")
        self._lock = Lock()
        self._jobs: dict[str, ScanJobRecord] = {}
        self._futures: dict[str, Future] = {}
        self._cancel_events: dict[str, Event] = {}

    def create_job(self, request: CreateScanRequest) -> ScanJobRecord:
        with self._lock:
            job_id = str(request.scan_id or len(self._jobs) + 1)
            record = ScanJobRecord(job_id=job_id, request=request)
            self._jobs[job_id] = record
            self._cancel_events[job_id] = Event()
            future = self._executor.submit(self._run_job, job_id)
            self._futures[job_id] = future
        return record

    def _run_job(self, job_id: str) -> None:
        with self._lock:
            record = self._jobs[job_id]
            cancel_event = self._cancel_events[job_id]
            if cancel_event.is_set():
                record.status = "aborted"
                record.finished_at = utc_now()
                return
            record.status = "running"
            record.started_at = utc_now()

        try:
            projection = run_scan_job(record.request, cancel_event=cancel_event).to_dict()
            with self._lock:
                record.projection = projection
                record.status = "aborted" if projection.get("status") == "aborted" else "finished"
                record.finished_at = utc_now()
        except Exception as exc:
            with self._lock:
                record.status = "aborted" if cancel_event.is_set() else "failed"
                record.finished_at = utc_now()
                record.error_message = None if cancel_event.is_set() else str(exc)

    def get_job(self, job_id: str) -> ScanJobRecord | None:
        with self._lock:
            return self._jobs.get(str(job_id))

    def get_projection(self, job_id: str) -> dict[str, Any] | None:
        record = self.get_job(job_id)
        return None if record is None else record.projection

    def terminate_job(self, job_id: str) -> ScanJobRecord | None:
        with self._lock:
            record = self._jobs.get(str(job_id))
            if record is None:
                return None

            cancel_event = self._cancel_events.get(str(job_id))
            if cancel_event is not None:
                cancel_event.set()

            if record.cancel_requested_at is None:
                record.cancel_requested_at = utc_now()

            future = self._futures.get(str(job_id))
            if record.status == "queued" and future is not None and future.cancel():
                record.status = "aborted"
                record.finished_at = utc_now()
                record.error_message = None
                return record

            if record.status in {"queued", "running"}:
                record.status = "aborting"

            return record

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)
