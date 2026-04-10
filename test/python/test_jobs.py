from __future__ import annotations

import time
import unittest
from unittest.mock import patch

from python.cti_service.jobs import JobManager
from python.cti_service.schemas import CreateScanRequest


class _FakeProjection:
    def __init__(self, status: str) -> None:
        self._status = status

    def to_dict(self) -> dict[str, object]:
        return {
            "scan_id": 6001,
            "scan_name": "Terminate Test",
            "root_target": "example.com",
            "status": self._status,
            "results": [],
            "events": [],
            "logs": [],
            "correlations": [],
            "type_counts": {},
            "parent_child_index": {},
        }


class JobManagerTests(unittest.TestCase):
    @patch("python.cti_service.jobs.run_scan_job")
    def test_terminate_job_marks_record_aborted(self, mock_run_scan_job) -> None:
        def fake_run_scan_job(request, cancel_event=None):
            deadline = time.time() + 1.0
            while cancel_event is not None and not cancel_event.is_set() and time.time() < deadline:
                time.sleep(0.01)
            return _FakeProjection("aborted" if cancel_event and cancel_event.is_set() else "finished")

        mock_run_scan_job.side_effect = fake_run_scan_job

        manager = JobManager(max_workers=1)
        try:
            request = CreateScanRequest.from_dict({
                "scan_id": 6001,
                "user_id": 1,
                "scan_name": "Terminate Test",
                "query_type": "domain",
                "query_value": "example.com",
                "selected_modules": ["dnsresolve"],
            })
            manager.create_job(request)
            record = manager.terminate_job("6001")

            self.assertIsNotNone(record)
            self.assertIsNotNone(record.cancel_requested_at)

            deadline = time.time() + 2.0
            while time.time() < deadline:
                refreshed = manager.get_job("6001")
                if refreshed and refreshed.status == "aborted":
                    break
                time.sleep(0.02)

            refreshed = manager.get_job("6001")
            self.assertIsNotNone(refreshed)
            self.assertEqual(refreshed.status, "aborted")
        finally:
            manager.shutdown()


if __name__ == "__main__":
    unittest.main()
