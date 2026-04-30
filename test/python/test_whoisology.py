from __future__ import annotations

import unittest

from python.cti_engine.context import ScanContext, ScanRequest
from python.cti_engine.events import ScanEvent
from python.cti_engine.modules.whoisology import WhoisologyModule
from python.cti_engine.settings import SettingsSnapshot
from python.cti_engine.targets import normalize_target


class WhoisologyModuleTests(unittest.TestCase):
    def test_payload_emits_reverse_whois_affiliate_domains(self) -> None:
        module = WhoisologyModule()
        request = ScanRequest(
            scan_id=18,
            user_id=1,
            scan_name="Whoisology Test",
            target=normalize_target("admin@example.com", "email"),
            selected_modules=["whoisology"],
            settings=SettingsSnapshot(),
        )
        ctx = ScanContext(request=request)
        parent = ScanEvent(
            event_type="email",
            value="admin@example.com",
            source_module="seed",
            root_target="admin@example.com",
        )

        payload = [
            {"domain_name": "related-one.com"},
            {"domain_name": "related-two.com"},
            {"domain_name": "related-one.com"},
            {"domain_name": "not-a-domain-value"},
        ]

        events = module._events_from_payload(payload, parent, ctx)
        event_types = [event.event_type for event in events]
        self.assertEqual(3, event_types.count("affiliate_internet_name"))
        self.assertEqual(2, event_types.count("affiliate_domain_name"))


if __name__ == "__main__":
    unittest.main()
