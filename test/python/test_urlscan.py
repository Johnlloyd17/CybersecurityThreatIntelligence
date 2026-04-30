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
            settings=SettingsSnapshot(module_settings={"urlscan": {"verify_hostnames": False}}),
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
                    "task": {
                        "time": "2026-04-10T03:00:00Z",
                        "url": "https://example.com/login",
                    },
                    "page": {
                        "url": "https://example.com/login",
                        "domain": "example.com",
                        "asn": "AS64500",
                        "city": "Pasig",
                        "country": "US",
                        "server": "ExampleServer",
                    },
                },
                {
                    "task": {
                        "time": "2026-04-10T03:01:00Z",
                        "url": "https://static.example.com/app.js",
                    },
                    "page": {
                        "domain": "static.example.com",
                        "asn": "AS64500",
                        "city": "Pasig",
                        "country": "US",
                        "server": "ExampleServer",
                    },
                }
            ]
        }

        events = module._events_from_payload(payload, parent, ctx)
        event_types = [event.event_type for event in events]
        self.assertIn("raw_rir_data", event_types)
        self.assertIn("linked_url_internal", event_types)
        self.assertIn("internet_name", event_types)
        self.assertIn("domain_name", event_types)
        self.assertIn("bgp_as_member", event_types)
        self.assertIn("webserver_banner", event_types)
        self.assertIn("physical_location", event_types)

    def test_url_payload_emits_expected_events(self) -> None:
        module = UrlscanModule()
        request = ScanRequest(
            scan_id=15,
            user_id=1,
            scan_name="urlscan URL Test",
            target=normalize_target("https://example.com/path", "url"),
            selected_modules=["urlscan"],
            settings=SettingsSnapshot(module_settings={"urlscan": {"verify_hostnames": False}}),
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
                    "task": {
                        "time": "2026-04-10T03:05:00Z",
                        "url": "https://example.com/path",
                    },
                    "page": {
                        "url": "https://example.com/path",
                        "domain": "example.com",
                        "asn": "AS15169",
                        "city": "Mountain View",
                        "country": "US",
                        "server": "ExampleServer",
                    },
                }
            ]
        }

        events = module._events_from_payload(payload, parent, ctx)
        event_types = [event.event_type for event in events]
        self.assertIn("raw_rir_data", event_types)
        self.assertIn("linked_url_internal", event_types)
        self.assertIn("internet_name", event_types)
        self.assertIn("domain_name", event_types)
        self.assertIn("bgp_as_member", event_types)


if __name__ == "__main__":
    unittest.main()
