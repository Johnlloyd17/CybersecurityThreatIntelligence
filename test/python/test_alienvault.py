from __future__ import annotations

import unittest

from python.cti_engine.context import ScanContext, ScanRequest
from python.cti_engine.events import ScanEvent
from python.cti_engine.settings import SettingsSnapshot
from python.cti_engine.targets import normalize_target
from python.cti_engine.modules.alienvault import AlienVaultModule


class AlienVaultModuleTests(unittest.TestCase):
    def test_domain_payload_parsing_emits_expected_events(self) -> None:
        module = AlienVaultModule()
        request = ScanRequest(
            scan_id=3,
            user_id=1,
            scan_name="OTX Test",
            target=normalize_target("example.com", "domain"),
            selected_modules=["alienvault"],
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
            "pulse_info": {
                "count": 2,
                "pulses": [
                    {
                        "name": "Test Pulse",
                        "indicators": [
                            {"type": "domain", "indicator": "mail.example.com"},
                            {"type": "URL", "indicator": "https://example.com/phish"},
                            {"type": "IPv4", "indicator": "8.8.8.8"},
                            {"type": "email", "indicator": "soc@example.com"},
                            {"type": "CVE", "indicator": "CVE-2024-1234"},
                            {"type": "FileHash-SHA256", "indicator": "a" * 64},
                        ],
                    }
                ],
            }
        }

        events = module._events_from_payload(payload, parent, ctx)
        event_types = [event.event_type for event in events]
        self.assertIn("malicious_domain", event_types)
        self.assertIn("internet_name", event_types)
        self.assertIn("linked_url_internal", event_types)
        self.assertIn("ip", event_types)
        self.assertIn("email", event_types)
        self.assertIn("cve", event_types)
        self.assertIn("hash", event_types)

    def test_domain_url_list_entries_emit_internal_urls(self) -> None:
        module = AlienVaultModule()
        request = ScanRequest(
            scan_id=4,
            user_id=1,
            scan_name="OTX URL List Test",
            target=normalize_target("elms.sti.edu", "domain"),
            selected_modules=["alienvault"],
            settings=SettingsSnapshot(),
        )
        ctx = ScanContext(request=request)
        parent = ScanEvent(
            event_type="domain",
            value="elms.sti.edu",
            source_module="seed",
            root_target="elms.sti.edu",
        )

        entries = [
            {"url": "https://elms.sti.edu/login"},
            {"url": "https://portal.elms.sti.edu/dashboard"},
            {"url": "https://google.com/outside"},
            {"url": "https://elms.sti.edu/login"},
        ]

        events = module._events_from_url_entries(entries, parent, ctx)
        values = [event.value for event in events]
        event_types = [event.event_type for event in events]

        self.assertEqual(event_types, ["linked_url_internal", "linked_url_internal"])
        self.assertIn("https://elms.sti.edu/login", values)
        self.assertIn("https://portal.elms.sti.edu/dashboard", values)
        self.assertNotIn("https://google.com/outside", values)


if __name__ == "__main__":
    unittest.main()
