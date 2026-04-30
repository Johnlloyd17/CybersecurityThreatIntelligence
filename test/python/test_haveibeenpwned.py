from __future__ import annotations

import unittest

from python.cti_engine.context import ScanContext, ScanRequest
from python.cti_engine.events import ScanEvent
from python.cti_engine.modules.haveibeenpwned import HaveIBeenPwnedModule
from python.cti_engine.settings import SettingsSnapshot
from python.cti_engine.targets import normalize_target


class HaveIBeenPwnedModuleTests(unittest.TestCase):
    def test_payload_emits_breached_email(self) -> None:
        module = HaveIBeenPwnedModule()
        request = ScanRequest(
            scan_id=77,
            user_id=1,
            scan_name="HIBP Test",
            target=normalize_target("user@example.com", "email"),
            selected_modules=["haveibeenpwned"],
            settings=SettingsSnapshot(),
        )
        ctx = ScanContext(request=request)
        parent = ScanEvent(event_type="email", value="user@example.com", source_module="seed", root_target="user@example.com")

        payload = [
            {"Name": "Adobe", "DataClasses": ["Email addresses", "Passwords"]},
            {"Name": "LinkedIn", "DataClasses": ["Email addresses"]},
        ]
        events = module._events_from_payload(payload, parent, ctx)
        event_types = [event.event_type for event in events]
        self.assertIn("raw_rir_data", event_types)
        self.assertIn("breached_email_address", event_types)


if __name__ == "__main__":
    unittest.main()
