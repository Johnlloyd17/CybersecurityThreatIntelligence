from __future__ import annotations

import unittest

from python.cti_engine.context import ScanContext, ScanRequest
from python.cti_engine.events import ScanEvent
from python.cti_engine.modules.whoxy import WhoxyModule
from python.cti_engine.settings import SettingsSnapshot
from python.cti_engine.targets import normalize_target


class WhoxyModuleTests(unittest.TestCase):
    def test_payload_emits_summary_and_nameservers(self) -> None:
        module = WhoxyModule()
        request = ScanRequest(
            scan_id=17,
            user_id=1,
            scan_name="Whoxy Test",
            target=normalize_target("example.com", "domain"),
            selected_modules=["whoxy"],
            settings=SettingsSnapshot(),
        )
        ctx = ScanContext(request=request)
        parent = ScanEvent(
            event_type="domain",
            value="example.com",
            source_module="seed",
            root_target="example.com",
        )

        payload = {
            "status": 1,
            "registrar_name": "Whoxy Registrar",
            "create_date": "2023-01-01",
            "expiry_date": "2027-01-01",
            "name_servers": ["ns1.example.net", "ns2.example.net"],
        }

        events = module._events_from_payload(payload, parent, ctx)
        event_types = [event.event_type for event in events]
        self.assertIn("whois_record", event_types)
        self.assertEqual(2, event_types.count("internet_name"))


if __name__ == "__main__":
    unittest.main()
