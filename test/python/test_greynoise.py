from __future__ import annotations

import unittest

from python.cti_engine.context import ScanContext, ScanRequest
from python.cti_engine.events import ScanEvent
from python.cti_engine.modules.greynoise import GreyNoiseModule
from python.cti_engine.settings import SettingsSnapshot
from python.cti_engine.targets import normalize_target


class GreyNoiseModuleTests(unittest.TestCase):
    def test_payload_emits_expected_events(self) -> None:
        module = GreyNoiseModule()
        request = ScanRequest(
            scan_id=36,
            user_id=1,
            scan_name="GreyNoise Test",
            target=normalize_target("8.8.8.8", "ip"),
            selected_modules=["greynoise"],
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
            "classification": "malicious",
            "name": "GreyNoise Test Sensor",
            "city": "Singapore",
            "country": "Singapore",
            "asn": "AS15169",
            "os": "Linux",
            "link": "https://viz.greynoise.io/ip/8.8.8.8",
        }
        events = module._events_from_payload(payload, parent, ctx)
        event_types = [event.event_type for event in events]
        self.assertIn("raw_rir_data", event_types)
        self.assertIn("malicious_ip", event_types)
        self.assertIn("company_name", event_types)
        self.assertIn("physical_location", event_types)
        self.assertIn("bgp_as_member", event_types)
        self.assertIn("operating_system", event_types)


if __name__ == "__main__":
    unittest.main()
