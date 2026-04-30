from __future__ import annotations

import unittest

from python.cti_engine.context import ScanContext, ScanRequest
from python.cti_engine.events import ScanEvent
from python.cti_engine.modules.ipregistry import IpRegistryModule
from python.cti_engine.settings import SettingsSnapshot
from python.cti_engine.targets import normalize_target


class IpRegistryModuleTests(unittest.TestCase):
    def test_payload_emits_org_geo_asn_and_privacy(self) -> None:
        module = IpRegistryModule()
        request = ScanRequest(
            scan_id=51,
            user_id=1,
            scan_name="ipregistry Test",
            target=normalize_target("1.1.1.1", "ip"),
            selected_modules=["ipregistry"],
            settings=SettingsSnapshot(),
        )
        ctx = ScanContext(request=request)
        parent = ScanEvent(event_type="ip", value="1.1.1.1", source_module="seed", root_target="1.1.1.1")

        payload = {
            "connection": {"organization": "Cloudflare", "asn": 13335},
            "location": {"city": "Sydney", "country": {"name": "Australia"}},
            "security": {"is_vpn": True, "is_proxy": False, "is_tor_exit": True},
        }
        events = module._events_from_payload(payload, parent, ctx)
        event_types = [event.event_type for event in events]
        self.assertIn("company_name", event_types)
        self.assertIn("bgp_as_member", event_types)
        self.assertIn("physical_location", event_types)
        self.assertIn("vpn_host", event_types)
        self.assertIn("tor_exit_node", event_types)


if __name__ == "__main__":
    unittest.main()
