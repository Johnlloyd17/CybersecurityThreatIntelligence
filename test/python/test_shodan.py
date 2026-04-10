from __future__ import annotations

import unittest

from python.cti_engine.context import ScanContext, ScanRequest
from python.cti_engine.events import ScanEvent
from python.cti_engine.modules.shodan import ShodanModule
from python.cti_engine.settings import SettingsSnapshot
from python.cti_engine.targets import normalize_target


class ShodanModuleTests(unittest.TestCase):
    def test_domain_resolution_creates_ip_event(self) -> None:
        module = ShodanModule()
        request = ScanRequest(
            scan_id=4,
            user_id=1,
            scan_name="Shodan Domain Test",
            target=normalize_target("example.com", "domain"),
            selected_modules=["shodan"],
            settings=SettingsSnapshot(),
        )
        ctx = ScanContext(request=request)
        parent = ScanEvent(
            event_type="domain",
            value="example.com",
            source_module="seed",
            root_target="example.com",
        )

        event = module._resolve_domain_to_ip_event("93.184.216.34", parent, ctx)
        self.assertEqual("ip", event.event_type)
        self.assertEqual("93.184.216.34", event.value)
        self.assertEqual(parent.event_id, event.parent_event_id)

    def test_host_payload_emits_expected_events(self) -> None:
        module = ShodanModule()
        request = ScanRequest(
            scan_id=5,
            user_id=1,
            scan_name="Shodan IP Test",
            target=normalize_target("8.8.8.8", "ip"),
            selected_modules=["shodan"],
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
            "ports": [53, 22, 443],
            "vulns": {"CVE-2024-1111": {}, "CVE-2024-2222": {}},
            "hostnames": ["dns.google"],
            "domains": ["google.com"],
        }

        events = module._events_from_host_payload(payload, parent, ctx)
        event_types = [event.event_type for event in events]
        self.assertIn("malicious_ip", event_types)
        self.assertIn("internet_name", event_types)
        self.assertIn("open_port", event_types)
        self.assertIn("cve", event_types)


if __name__ == "__main__":
    unittest.main()
