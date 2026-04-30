from __future__ import annotations

import unittest

from python.cti_engine.context import ScanContext, ScanRequest
from python.cti_engine.events import ScanEvent
from python.cti_engine.modules.censys import CensysModule
from python.cti_engine.settings import SettingsSnapshot
from python.cti_engine.targets import normalize_target


class CensysModuleTests(unittest.TestCase):
    def test_domain_search_payload_emits_ips(self) -> None:
        module = CensysModule()
        request = ScanRequest(
            scan_id=48,
            user_id=1,
            scan_name="Censys Domain Test",
            target=normalize_target("example.com", "domain"),
            selected_modules=["censys"],
            settings=SettingsSnapshot(),
        )
        ctx = ScanContext(request=request)
        parent = ScanEvent(event_type="domain", value="example.com", source_module="seed", root_target="example.com")

        payload = {"result": {"hits": [{"ip": "1.1.1.1"}, {"ip": "8.8.8.8"}]}}
        events = module._events_from_payload(payload, parent, ctx)
        event_types = [event.event_type for event in events]
        self.assertIn("raw_rir_data", event_types)
        self.assertIn("ip", event_types)

    def test_ip_host_payload_emits_host_details(self) -> None:
        module = CensysModule()
        request = ScanRequest(
            scan_id=49,
            user_id=1,
            scan_name="Censys IP Test",
            target=normalize_target("8.8.8.8", "ip"),
            selected_modules=["censys"],
            settings=SettingsSnapshot(),
        )
        ctx = ScanContext(request=request)
        parent = ScanEvent(event_type="ip", value="8.8.8.8", source_module="seed", root_target="8.8.8.8")

        payload = {
            "result": {
                "location": {"city": "Mountain View", "country": "US"},
                "autonomous_system": {"asn": 15169},
                "services": [{"port": 53, "service_name": "dns", "operating_system": "Linux"}],
            }
        }
        events = module._events_from_payload(payload, parent, ctx)
        event_types = [event.event_type for event in events]
        self.assertIn("open_port", event_types)
        self.assertIn("software_used", event_types)
        self.assertIn("bgp_as_member", event_types)
        self.assertIn("physical_location", event_types)


if __name__ == "__main__":
    unittest.main()
