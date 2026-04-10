from __future__ import annotations

import unittest

from python.cti_engine.context import ScanContext, ScanRequest
from python.cti_engine.events import ScanEvent
from python.cti_engine.modules.abusech import AbuseChModule
from python.cti_engine.settings import SettingsSnapshot
from python.cti_engine.targets import normalize_target


class AbuseChModuleTests(unittest.TestCase):
    def test_host_payload_emits_expected_events(self) -> None:
        module = AbuseChModule()
        request = ScanRequest(
            scan_id=8,
            user_id=1,
            scan_name="abuse.ch Host Test",
            target=normalize_target("bad.example", "domain"),
            selected_modules=["abuse-ch"],
            settings=SettingsSnapshot(),
        )
        ctx = ScanContext(request=request)
        parent = ScanEvent(
            event_type="domain",
            value="bad.example",
            source_module="seed",
            root_target="bad.example",
        )

        payload = {
            "query_status": "ok",
            "url_count": 2,
            "urls_online": 1,
            "urls": [
                {"url": "https://bad.example/payload.exe", "threat": "malware_download", "url_status": "online"},
                {"url": "https://bad.example/phish", "threat": "phishing", "url_status": "offline"},
            ],
        }

        events = module._events_from_payload(payload, parent, ctx)
        event_types = [event.event_type for event in events]
        self.assertIn("malicious_domain", event_types)
        self.assertIn("linked_url_internal", event_types)

    def test_url_payload_emits_malicious_url_and_hostname(self) -> None:
        module = AbuseChModule()
        request = ScanRequest(
            scan_id=9,
            user_id=1,
            scan_name="abuse.ch URL Test",
            target=normalize_target("https://bad.example/phish", "url"),
            selected_modules=["abuse-ch"],
            settings=SettingsSnapshot(),
        )
        ctx = ScanContext(request=request)
        parent = ScanEvent(
            event_type="url",
            value="https://bad.example/phish",
            source_module="seed",
            root_target="https://bad.example/phish",
        )

        payload = {
            "query_status": "ok",
            "threat": "phishing",
            "url_status": "online",
            "date_added": "2026-04-10 00:00:00",
        }

        events = module._events_from_payload(payload, parent, ctx)
        event_types = [event.event_type for event in events]
        self.assertIn("malicious_url", event_types)
        self.assertIn("internet_name", event_types)


if __name__ == "__main__":
    unittest.main()
