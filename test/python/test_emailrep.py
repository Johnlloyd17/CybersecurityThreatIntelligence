from __future__ import annotations

import unittest

from python.cti_engine.context import ScanContext, ScanRequest
from python.cti_engine.events import ScanEvent
from python.cti_engine.modules.emailrep import EmailRepModule
from python.cti_engine.settings import SettingsSnapshot
from python.cti_engine.targets import normalize_target


class EmailRepModuleTests(unittest.TestCase):
    def test_payload_emits_spiderfoot_style_malicious_and_compromised_events(self) -> None:
        module = EmailRepModule()
        request = ScanRequest(
            scan_id=74,
            user_id=1,
            scan_name="EmailRep Test",
            target=normalize_target("breached@example.com", "email"),
            selected_modules=["emailrep"],
            settings=SettingsSnapshot(),
        )
        ctx = ScanContext(request=request)
        parent = ScanEvent(
            event_type="email",
            value="breached@example.com",
            source_module="seed",
            root_target="breached@example.com",
        )

        payload = {
            "details": {
                "credentials_leaked": True,
                "malicious_activity": True,
                "disposable": True,
            },
        }
        events = module._events_from_payload(payload, parent, ctx)
        event_types = [event.event_type for event in events]
        self.assertIn("raw_rir_data", event_types)
        self.assertIn("malicious_email_address", event_types)
        self.assertIn("breached_email_address", event_types)
        self.assertNotIn("disposable_email_address", event_types)

    def test_benign_payload_emits_nothing(self) -> None:
        module = EmailRepModule()
        request = ScanRequest(
            scan_id=75,
            user_id=1,
            scan_name="EmailRep Benign Test",
            target=normalize_target("user@example.com", "email"),
            selected_modules=["emailrep"],
            settings=SettingsSnapshot(),
        )
        ctx = ScanContext(request=request)
        parent = ScanEvent(
            event_type="email",
            value="user@example.com",
            source_module="seed",
            root_target="user@example.com",
        )

        self.assertEqual([], module._events_from_payload({"details": {"credentials_leaked": False, "malicious_activity": False}}, parent, ctx))


if __name__ == "__main__":
    unittest.main()
