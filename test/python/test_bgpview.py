from __future__ import annotations

import unittest

from python.cti_engine.context import ScanContext, ScanRequest
from python.cti_engine.events import ScanEvent
from python.cti_engine.modules.bgpview import BgpViewModule
from python.cti_engine.settings import SettingsSnapshot
from python.cti_engine.targets import normalize_target


class BgpViewModuleTests(unittest.TestCase):
    def test_ip_payload_emits_spiderfoot_style_asn_and_netblock_events(self) -> None:
        module = BgpViewModule()
        request = ScanRequest(
            scan_id=54,
            user_id=1,
            scan_name="BGPView IP Test",
            target=normalize_target("8.8.8.8", "ip"),
            selected_modules=["bgpview"],
            settings=SettingsSnapshot(),
        )
        ctx = ScanContext(request=request)
        parent = ScanEvent(event_type="ip", value="8.8.8.8", source_module="seed", root_target="8.8.8.8")

        payload = {
            "status": "ok",
            "data": {
                "prefixes": [
                    {"asn": {"asn": 15169}, "prefix": "8.8.8.0/24", "name": "Google"},
                ]
            },
        }
        events = module._events_from_ip_payload(payload, parent, ctx)
        event_types = [event.event_type for event in events]
        self.assertIn("raw_rir_data", event_types)
        self.assertIn("bgp_as_member", event_types)
        self.assertIn("netblock_member", event_types)

    def test_owner_payload_emits_physical_address(self) -> None:
        module = BgpViewModule()
        request = ScanRequest(
            scan_id=55,
            user_id=1,
            scan_name="BGPView ASN Test",
            target=normalize_target("AS15169", "bgp_as_member"),
            selected_modules=["bgpview"],
            settings=SettingsSnapshot(),
        )
        ctx = ScanContext(request=request)
        parent = ScanEvent(
            event_type="bgp_as_member",
            value="15169",
            source_module="seed",
            root_target="AS15169",
        )

        payload = {
            "status": "ok",
            "data": {
                "owner_address": ["1600 Amphitheatre Parkway", "Mountain View", "US"],
            },
        }

        events = module._events_from_owner_payload(payload, parent, ctx)
        event_types = [event.event_type for event in events]
        self.assertIn("raw_rir_data", event_types)
        self.assertIn("physical_address", event_types)


if __name__ == "__main__":
    unittest.main()
