"""Minimal HTTP service shell for the CTI Python engine."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import re
from typing import Any

from .config import ServiceConfig
from .jobs import JobManager
from .schemas import CreateScanRequest


SCAN_DETAIL_RX = re.compile(r"^/api/v1/scans/([^/]+)$")
SCAN_LOGS_RX = re.compile(r"^/api/v1/scans/([^/]+)/logs$")
SCAN_RESULTS_RX = re.compile(r"^/api/v1/scans/([^/]+)/results$")
SCAN_TERMINATE_RX = re.compile(r"^/api/v1/scans/([^/]+)/terminate$")


def json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=False).encode("utf-8")


def build_handler(job_manager: JobManager):
    class Handler(BaseHTTPRequestHandler):
        server_version = "CTIEngineService/0.1"

        def _read_json_body(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0") or 0)
            raw = self.rfile.read(length) if length > 0 else b"{}"
            payload = json.loads(raw.decode("utf-8") or "{}")
            if not isinstance(payload, dict):
                raise ValueError("JSON body must be an object")
            return payload

        def _send_json(self, status: int, payload: dict[str, Any]) -> None:
            body = json_bytes(payload)
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/":
                self._send_json(
                    200,
                    {
                        "service": "cti-python-engine",
                        "status": "running",
                        "version": "0.1",
                        "routes": {
                            "health": "/health",
                            "create_scan": "/api/v1/scans",
                            "scan_detail": "/api/v1/scans/{scan_id}",
                            "scan_logs": "/api/v1/scans/{scan_id}/logs",
                            "scan_results": "/api/v1/scans/{scan_id}/results",
                            "terminate_scan": "/api/v1/scans/{scan_id}/terminate",
                        },
                        "message": "CTI Python engine service is running.",
                    },
                )
                return

            if self.path == "/health":
                self._send_json(200, {"status": "ok"})
                return

            match = SCAN_DETAIL_RX.match(self.path)
            if match:
                record = job_manager.get_job(match.group(1))
                if record is None:
                    self._send_json(404, {"error": "Scan not found"})
                    return
                self._send_json(200, record.summary())
                return

            match = SCAN_LOGS_RX.match(self.path)
            if match:
                projection = job_manager.get_projection(match.group(1))
                if projection is None:
                    self._send_json(404, {"error": "Logs not found"})
                    return
                self._send_json(200, {"logs": projection.get("logs", [])})
                return

            match = SCAN_RESULTS_RX.match(self.path)
            if match:
                projection = job_manager.get_projection(match.group(1))
                if projection is None:
                    self._send_json(404, {"error": "Results not found"})
                    return
                self._send_json(200, projection)
                return

            self._send_json(404, {"error": "Not found"})

        def do_POST(self) -> None:  # noqa: N802
            match = SCAN_TERMINATE_RX.match(self.path)
            if match:
                record = job_manager.terminate_job(match.group(1))
                if record is None:
                    self._send_json(404, {"error": "Scan not found"})
                    return
                self._send_json(200, record.summary())
                return

            if self.path != "/api/v1/scans":
                self._send_json(404, {"error": "Not found"})
                return

            try:
                payload = self._read_json_body()
                request = CreateScanRequest.from_dict(payload)
                record = job_manager.create_job(request)
            except Exception as exc:
                self._send_json(400, {"error": str(exc)})
                return

            self._send_json(202, record.summary())

        def log_message(self, format: str, *args: Any) -> None:
            return

    return Handler


def run_server(config: ServiceConfig | None = None) -> None:
    service_config = config or ServiceConfig.from_env()
    job_manager = JobManager(max_workers=service_config.max_workers)
    handler = build_handler(job_manager)
    server = ThreadingHTTPServer((service_config.host, service_config.port), handler)
    try:
        print(
            json.dumps(
                {
                    "service": "cti-python-engine",
                    "host": service_config.host,
                    "port": service_config.port,
                },
                ensure_ascii=False,
            ),
            flush=True,
        )
        server.serve_forever()
    finally:
        job_manager.shutdown()
        server.server_close()


if __name__ == "__main__":
    run_server()
