from __future__ import annotations

import unittest

from python.cti_engine.context import ScanContext, ScanRequest
from python.cti_engine.events import ScanEvent
from python.cti_engine.modules.urlscan import UrlscanModule
from python.cti_engine.settings import SettingsSnapshot
from python.cti_engine.targets import normalize_target


class UrlscanModuleTests(unittest.TestCase):
    def test_domain_payload_emits_expected_events(self) -> None:
        module = UrlscanModule()
        request = ScanRequest(
            scan_id=14,
            user_id=1,
            scan_name="urlscan Domain Test",
            target=normalize_target("example.com", "domain"),
            selected_modules=["urlscan"],
            settings=SettingsSnapshot(),
        )
        ctx = ScanContext(request=request)
        parent = ScanEvent(
            event_type="domain",
            value="example.com",
            source_module="seed",
            root_target="example.com",
        )

        payload = {
            "results": [
                {
                    "task": {"time": "2026-04-10T03:00:00Z"},
                    "page": {
                        "url": "https://example.com/login",
                        "domain": "example.com",
                        "ip": "93.184.216.34",
                        "country": "US",
                        "server": "ExampleServer",
                    },
                    "verdicts": {
                        "overall": {
                            "malicious": True,
                            "categories": ["phishing"],
                        }
                    },
                }
            ]
        }

        events = module._events_from_payload(payload, parent, ctx)
        event_types = [event.event_type for event in events]
        self.assertIn("malicious_domain", event_types)
        self.assertIn("linked_url_internal", event_types)
        self.assertIn("ip", event_types)

    def test_url_payload_emits_expected_events(self) -> None:
        module = UrlscanModule()
        request = ScanRequest(
            scan_id=15,
            user_id=1,
            scan_name="urlscan URL Test",
            target=normalize_target("https://example.com/path", "url"),
            selected_modules=["urlscan"],
            settings=SettingsSnapshot(),
        )
        ctx = ScanContext(request=request)
        parent = ScanEvent(
            event_type="url",
            value="https://example.com/path",
            source_module="seed",
            root_target="https://example.com/path",
        )

        payload = {
            "results": [
                {
                    "task": {"time": "2026-04-10T03:05:00Z"},
                    "page": {
                        "url": "https://example.com/path",
                        "domain": "example.com",
                        "ip": "93.184.216.34",
                    },
                    "verdicts": {
                        "overall": {
                            "malicious": True,
                            "categories": ["malware"],
                        }
                    },
                }
            ]
        }

        events = module._events_from_payload(payload, parent, ctx)
        event_types = [event.event_type for event in events]
        self.assertIn("malicious_url", event_types)
        self.assertIn("internet_name", event_types)
        self.assertIn("ip", event_types)


if __name__ == "__main__":
    unittest.main()
