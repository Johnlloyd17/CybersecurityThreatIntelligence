from __future__ import annotations

import unittest

from python.cti_engine.context import ScanContext, ScanRequest
from python.cti_engine.events import ScanEvent
from python.cti_engine.modules.ipinfo import IpInfoModule
from python.cti_engine.settings import SettingsSnapshot
from python.cti_engine.targets import normalize_target


class IpInfoModuleTests(unittest.TestCase):
    def test_payload_emits_org_geo_and_privacy_events(self) -> None:
        module = IpInfoModule()
        request = ScanRequest(
            scan_id=50,
            user_id=1,
            scan_name="IPInfo Test",
            target=normalize_target("8.8.8.8", "ip"),
            selected_modules=["ipinfo"],
            settings=SettingsSnapshot(),
        )
        ctx = ScanContext(request=request)
        parent = ScanEvent(event_type="ip", value="8.8.8.8", source_module="seed", root_target="8.8.8.8")

        payload = {
            "hostname": "dns.google",
            "city": "Mountain View",
            "country": "US",
            "org": "AS15169 Google LLC",
            "privacy": {"vpn": True, "proxy": True, "tor": False},
        }
        events = module._events_from_payload(payload, parent, ctx)
        event_types = [event.event_type for event in events]
        self.assertIn("internet_name", event_types)
        self.assertIn("company_name", event_types)
        self.assertIn("bgp_as_member", event_types)
        self.assertIn("physical_location", event_types)
        self.assertIn("vpn_host", event_types)
        self.assertIn("proxy_host", event_types)


if __name__ == "__main__":
    unittest.main()
