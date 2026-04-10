from __future__ import annotations

import unittest

from python.cti_engine.context import ScanContext, ScanRequest
from python.cti_engine.events import ScanEvent
from python.cti_engine.settings import SettingsSnapshot
from python.cti_engine.targets import normalize_target
from python.cti_engine.modules.virustotal import VirusTotalModule


class VirusTotalModuleTests(unittest.TestCase):
    def test_domain_payload_parsing_emits_expected_events(self) -> None:
        module = VirusTotalModule()
        request = ScanRequest(
            scan_id=2,
            user_id=1,
            scan_name="VT Test",
            target=normalize_target("example.com", "domain"),
            selected_modules=["virustotal"],
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
            "detected_urls": [{"url": "https://example.com/phish", "positives": 5}],
            "subdomains": ["mail.example.com"],
            "domain_siblings": ["cdn.example.net"],
        }

        events = module._events_from_payload(payload, parent, ctx)
        event_types = [event.event_type for event in events]
        self.assertIn("malicious_domain", event_types)
        self.assertIn("linked_url_internal", event_types)
        self.assertIn("internet_name", event_types)


if __name__ == "__main__":
    unittest.main()

