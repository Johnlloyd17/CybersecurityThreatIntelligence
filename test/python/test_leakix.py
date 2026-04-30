from __future__ import annotations

import unittest

from python.cti_engine.context import ScanContext, ScanRequest
from python.cti_engine.events import ScanEvent
from python.cti_engine.modules.leakix import LeakIxModule
from python.cti_engine.settings import SettingsSnapshot
from python.cti_engine.targets import normalize_target


class LeakIxModuleTests(unittest.TestCase):
    def test_ip_payload_emits_spiderfoot_style_host_service_and_leak_events(self) -> None:
        module = LeakIxModule()
        request = ScanRequest(
            scan_id=80,
            user_id=1,
            scan_name="LeakIX IP Test",
            target=normalize_target("8.8.8.8", "ip"),
            selected_modules=["leakix"],
            settings=SettingsSnapshot(),
        )
        ctx = ScanContext(request=request)
        parent = ScanEvent(event_type="ip", value="8.8.8.8", source_module="seed", root_target="8.8.8.8")

        payload = {
            "Services": [
                {
                    "host": "dns.google",
                    "ip": "8.8.8.8",
                    "port": "443",
                    "headers": {"Server": ["Google Frontend"]},
                    "geoip": {"city_name": "Mountain View", "country_name": "United States"},
                    "software": {"name": "nginx", "version": "1.25.0", "os": "Linux"},
                }
            ],
            "Leaks": [{"type": "db", "data": "dumped rows"}],
        }
        events = module._events_from_host_payload(payload, parent, ctx)
        event_types = [event.event_type for event in events]
        self.assertIn("raw_rir_data", event_types)
        self.assertIn("open_tcp_port", event_types)
        self.assertIn("webserver_banner", event_types)
        self.assertIn("physical_location", event_types)
        self.assertIn("software_used", event_types)
        self.assertIn("operating_system", event_types)
        self.assertIn("leaksite_content", event_types)

    def test_email_search_payload_emits_breached_email(self) -> None:
        module = LeakIxModule()
        request = ScanRequest(
            scan_id=81,
            user_id=1,
            scan_name="LeakIX Email Test",
            target=normalize_target("user@example.com", "email"),
            selected_modules=["leakix"],
            settings=SettingsSnapshot(),
        )
        ctx = ScanContext(request=request)
        parent = ScanEvent(event_type="email", value="user@example.com", source_module="seed", root_target="user@example.com")

        payload = [{"host": "portal.example.com"}]
        events = module._events_from_email_payload(payload, parent, ctx)
        event_types = [event.event_type for event in events]
        self.assertIn("raw_rir_data", event_types)
        self.assertIn("breached_email_address", event_types)
        self.assertIn("internet_name", event_types)


if __name__ == "__main__":
    unittest.main()
