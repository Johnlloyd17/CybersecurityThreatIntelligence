from __future__ import annotations

import unittest

from python.cti_engine.context import ScanContext, ScanRequest
from python.cti_engine.events import ScanEvent
from python.cti_engine.modules.abuseipdb import AbuseIpDbModule
from python.cti_engine.settings import SettingsSnapshot
from python.cti_engine.targets import normalize_target


class AbuseIpDbModuleTests(unittest.TestCase):
    def test_payload_parsing_emits_expected_events(self) -> None:
        module = AbuseIpDbModule()
        request = ScanRequest(
            scan_id=6,
            user_id=1,
            scan_name="AbuseIPDB Test",
            target=normalize_target("118.25.6.39", "ip"),
            selected_modules=["abuseipdb"],
            settings=SettingsSnapshot(),
        )
        ctx = ScanContext(request=request)
        parent = ScanEvent(
            event_type="ip",
            value="118.25.6.39",
            source_module="seed",
            root_target="118.25.6.39",
        )

        payload = {
            "abuseConfidenceScore": 100,
            "totalReports": 26,
            "domain": "example-abusive.test",
            "isp": "Example ISP",
            "usageType": "Data Center/Web Hosting/Transit",
            "lastReportedAt": "2026-04-10T00:00:00+00:00",
        }

        events = module._events_from_payload(payload, parent, ctx)
        event_types = [event.event_type for event in events]
        self.assertIn("malicious_ip", event_types)
        self.assertIn("internet_name", event_types)

    def test_clean_payload_without_domain_emits_no_events(self) -> None:
        module = AbuseIpDbModule()
        request = ScanRequest(
            scan_id=7,
            user_id=1,
            scan_name="AbuseIPDB Clean Test",
            target=normalize_target("8.8.8.8", "ip"),
            selected_modules=["abuseipdb"],
            settings=SettingsSnapshot(),
        )
        ctx = ScanContext(request=request)
        parent = ScanEvent(
            event_type="ip",
            value="8.8.8.8",
            source_module="seed",
            root_target="8.8.8.8",
        )

        payload = {
            "abuseConfidenceScore": 0,
            "totalReports": 0,
            "domain": "",
        }

        events = module._events_from_payload(payload, parent, ctx)
        self.assertEqual([], events)


if __name__ == "__main__":
    unittest.main()
