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
            "os": "Linux",
            "devtype": "router",
            "city": "Mountain View",
            "country_name": "United States",
            "data": [
                {
                    "port": 53,
                    "banner": "DNS service banner",
                    "product": "dnsmasq",
                    "asn": "AS15169",
                    "vulns": {
                        "CVE-2024-1111": {"cvss": 9.8},
                        "CVE-2024-2222": {"cvss": 6.5},
                    },
                },
                {
                    "port": 443,
                    "banner": "HTTPS banner",
                    "product": "nginx",
                    "asn": "AS15169",
                },
            ],
        }

        events = module._events_from_host_payload(payload, parent, ctx)
        event_types = [event.event_type for event in events]
        self.assertIn("raw_rir_data", event_types)
        self.assertIn("operating_system", event_types)
        self.assertIn("device_type", event_types)
        self.assertIn("physical_location", event_types)
        self.assertIn("open_port", event_types)
        self.assertIn("open_port_banner", event_types)
        self.assertIn("software_used", event_types)
        self.assertIn("bgp_as_member", event_types)
        self.assertIn("vulnerability_cve_critical", event_types)
        self.assertIn("vulnerability_cve_medium", event_types)

    def test_vuln_event_type_maps_cvss_bands(self) -> None:
        module = ShodanModule()

        self.assertEqual("vulnerability_cve_critical", module._vuln_event_type("CVE-2024-0001", {"cvss": 9.5}))
        self.assertEqual("vulnerability_cve_high", module._vuln_event_type("CVE-2024-0002", {"cvss": 8.1}))
        self.assertEqual("vulnerability_cve_medium", module._vuln_event_type("CVE-2024-0003", {"cvss": 5.2}))
        self.assertEqual("vulnerability_cve_low", module._vuln_event_type("CVE-2024-0004", {"cvss": 2.3}))
        self.assertEqual("vulnerability_general", module._vuln_event_type("CVE-2024-0005", {}))


if __name__ == "__main__":
    unittest.main()
