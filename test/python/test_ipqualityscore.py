from __future__ import annotations

import unittest

from python.cti_engine.context import ScanContext, ScanRequest
from python.cti_engine.events import ScanEvent
from python.cti_engine.modules.ipqualityscore import IpQualityScoreModule
from python.cti_engine.settings import SettingsSnapshot
from python.cti_engine.targets import normalize_target


class IpQualityScoreModuleTests(unittest.TestCase):
    def test_ip_payload_emits_malicious_and_privacy_events(self) -> None:
        module = IpQualityScoreModule()
        request = ScanRequest(
            scan_id=52,
            user_id=1,
            scan_name="IPQS IP Test",
            target=normalize_target("8.8.8.8", "ip"),
            selected_modules=["ipqualityscore"],
            settings=SettingsSnapshot(),
        )
        ctx = ScanContext(request=request)
        parent = ScanEvent(event_type="ip", value="8.8.8.8", source_module="seed", root_target="8.8.8.8")

        payload = {"success": True, "fraud_score": 88, "vpn": True, "proxy": True, "tor": False}
        events = module._events_from_payload(payload, parent, ctx)
        event_types = [event.event_type for event in events]
        self.assertIn("malicious_ip", event_types)
        self.assertIn("vpn_host", event_types)
        self.assertIn("proxy_host", event_types)

    def test_email_payload_emits_disposable_and_invalid(self) -> None:
        module = IpQualityScoreModule()
        request = ScanRequest(
            scan_id=53,
            user_id=1,
            scan_name="IPQS Email Test",
            target=normalize_target("user@example.com", "email"),
            selected_modules=["ipqualityscore"],
            settings=SettingsSnapshot(),
        )
        ctx = ScanContext(request=request)
        parent = ScanEvent(event_type="email", value="user@example.com", source_module="seed", root_target="user@example.com")

        payload = {"success": True, "fraud_score": 45, "disposable": True, "valid": False}
        events = module._events_from_payload(payload, parent, ctx)
        event_types = [event.event_type for event in events]
        self.assertIn("disposable_email_address", event_types)
        self.assertIn("undeliverable_email_address", event_types)


if __name__ == "__main__":
    unittest.main()
