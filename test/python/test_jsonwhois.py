from __future__ import annotations

import unittest

from python.cti_engine.context import ScanContext, ScanRequest
from python.cti_engine.events import ScanEvent
from python.cti_engine.modules.jsonwhois import JsonWhoisModule
from python.cti_engine.settings import SettingsSnapshot
from python.cti_engine.targets import normalize_target


class JsonWhoisModuleTests(unittest.TestCase):
    def test_payload_emits_spiderfoot_style_whois_events(self) -> None:
        module = JsonWhoisModule()
        request = ScanRequest(
            scan_id=16,
            user_id=1,
            scan_name="JsonWHOIS Test",
            target=normalize_target("example.com", "domain"),
            selected_modules=["jsonwhois"],
            settings=SettingsSnapshot(
                global_settings={"generic_usernames": "abuse,admin,hostmaster"}
            ),
        )
        ctx = ScanContext(request=request)
        parent = ScanEvent(
            event_type="domain",
            value="example.com",
            source_module="seed",
            root_target="example.com",
        )

        payload = {
            "raw": "RAW WHOIS DATA",
            "registrar": {"name": "Example Registrar"},
            "nameservers": [{"name": "ns1.example.net"}, {"name": "ns2.example.net"}],
            "registrant_contacts": [
                {
                    "email": "admin@example.com",
                    "name": "Example Admin",
                    "phone": "+1 (555) 123-4567",
                    "address": "123 Main St",
                    "city": "Metro City",
                    "state": "State",
                    "zip": "1000",
                    "country_code": "US",
                }
            ],
            "admin_contacts": [
                {
                    "email": "owner@other.org",
                    "name": "Outside Owner",
                }
            ],
        }

        events = module._events_from_payload(payload, parent, ctx)
        event_types = [event.event_type for event in events]
        self.assertIn("raw_rir_data", event_types)
        self.assertIn("domain_whois", event_types)
        self.assertIn("domain_registrar", event_types)
        self.assertEqual(2, event_types.count("provider_dns"))
        self.assertIn("email_generic", event_types)
        self.assertIn("affiliate_email", event_types)
        self.assertIn("phone_number", event_types)
        self.assertIn("physical_address", event_types)


if __name__ == "__main__":
    unittest.main()
