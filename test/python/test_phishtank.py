from __future__ import annotations

import unittest

from python.cti_engine.context import ScanContext, ScanRequest
from python.cti_engine.events import ScanEvent
from python.cti_engine.modules.phishtank import PhishTankModule
from python.cti_engine.settings import SettingsSnapshot
from python.cti_engine.targets import normalize_target


class PhishTankModuleTests(unittest.TestCase):
    def test_domain_payload_emits_malicious_and_blacklisted_domain_events(self) -> None:
        module = PhishTankModule()
        request = ScanRequest(
            scan_id=34,
            user_id=1,
            scan_name="PhishTank Domain Test",
            target=normalize_target("bad.example", "domain"),
            selected_modules=["phishtank"],
            settings=SettingsSnapshot(),
        )
        ctx = ScanContext(request=request)
        parent = ScanEvent(
            event_type="domain",
            value="bad.example",
            source_module="seed",
            root_target="bad.example",
        )
        payload = [("12345", "bad.example")]
        events = module._events_from_domain_payload(payload, parent, ctx)
        event_types = [event.event_type for event in events]
        self.assertIn("malicious_internet_name", event_types)
        self.assertIn("blacklisted_internet_name", event_types)

    def test_url_payload_emits_malicious_url_and_hostname(self) -> None:
        module = PhishTankModule()
        request = ScanRequest(
            scan_id=35,
            user_id=1,
            scan_name="PhishTank URL Test",
            target=normalize_target("https://bad.example/login", "url"),
            selected_modules=["phishtank"],
            settings=SettingsSnapshot(),
        )
        ctx = ScanContext(request=request)
        parent = ScanEvent(
            event_type="url",
            value="https://bad.example/login",
            source_module="seed",
            root_target="https://bad.example/login",
        )
        payload = {
            "results": {
                "in_database": True,
                "valid": True,
                "phish_id": "999",
                "verified": True,
            }
        }
        events = module._events_from_url_payload(payload, parent, ctx)
        event_types = [event.event_type for event in events]
        self.assertIn("malicious_url", event_types)
        self.assertIn("internet_name", event_types)


if __name__ == "__main__":
    unittest.main()
