from __future__ import annotations

import unittest

from python.cti_engine.context import ScanContext, ScanRequest
from python.cti_engine.events import ScanEvent
from python.cti_engine.modules.hunter import HunterModule
from python.cti_engine.settings import SettingsSnapshot
from python.cti_engine.targets import normalize_target


class HunterModuleTests(unittest.TestCase):
    def test_domain_payload_emits_emails_and_company(self) -> None:
        module = HunterModule()
        request = ScanRequest(
            scan_id=75,
            user_id=1,
            scan_name="Hunter Domain Test",
            target=normalize_target("example.com", "domain"),
            selected_modules=["hunter"],
            settings=SettingsSnapshot(),
        )
        ctx = ScanContext(request=request)
        parent = ScanEvent(event_type="domain", value="example.com", source_module="seed", root_target="example.com")

        payload = {
            "organization": "Example Org",
            "emails": [
                {"value": "security@example.com", "generic": True},
                {"value": "alice@example.com", "generic": False},
            ],
        }
        events = module._events_from_payload(payload, parent, ctx)
        event_types = [event.event_type for event in events]
        self.assertIn("company_name", event_types)
        self.assertIn("email_generic", event_types)
        self.assertIn("email", event_types)

    def test_email_payload_emits_delivery_flags(self) -> None:
        module = HunterModule()
        request = ScanRequest(
            scan_id=76,
            user_id=1,
            scan_name="Hunter Email Test",
            target=normalize_target("user@example.com", "email"),
            selected_modules=["hunter"],
            settings=SettingsSnapshot(),
        )
        ctx = ScanContext(request=request)
        parent = ScanEvent(event_type="email", value="user@example.com", source_module="seed", root_target="user@example.com")

        payload = {
            "status": "invalid",
            "result": "undeliverable",
            "disposable": True,
        }
        events = module._events_from_payload(payload, parent, ctx)
        event_types = [event.event_type for event in events]
        self.assertIn("undeliverable_email_address", event_types)
        self.assertIn("disposable_email_address", event_types)


if __name__ == "__main__":
    unittest.main()
