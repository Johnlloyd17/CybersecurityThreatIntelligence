from __future__ import annotations

import unittest

from python.cti_engine.context import ScanContext, ScanRequest
from python.cti_engine.events import ScanEvent
from python.cti_engine.modules.viewdns import ViewDnsModule
from python.cti_engine.settings import SettingsSnapshot
from python.cti_engine.targets import normalize_target


class ViewDnsModuleTests(unittest.TestCase):
    def test_domain_payload_emits_dns_rows_and_children(self) -> None:
        module = ViewDnsModule()
        request = ScanRequest(
            scan_id=42,
            user_id=1,
            scan_name="ViewDNS Domain Test",
            target=normalize_target("example.com", "domain"),
            selected_modules=["viewdns"],
            settings=SettingsSnapshot(),
        )
        ctx = ScanContext(request=request)
        parent = ScanEvent(
            event_type="domain",
            value="example.com",
            source_module="seed",
            root_target="example.com",
        )

        payload = {"records": [{"type": "A", "data": "8.8.8.8"}, {"type": "NS", "data": "ns1.example.com"}]}
        events = module._events_from_payload(payload, parent, ctx)
        event_types = [event.event_type for event in events]

        self.assertIn("raw_rir_data", event_types)
        self.assertIn("raw_dns_records", event_types)
        self.assertIn("ip", event_types)
        self.assertIn("internet_name", event_types)

    def test_ip_payload_emits_cohosts(self) -> None:
        module = ViewDnsModule()
        request = ScanRequest(
            scan_id=43,
            user_id=1,
            scan_name="ViewDNS IP Test",
            target=normalize_target("8.8.8.8", "ip"),
            selected_modules=["viewdns"],
            settings=SettingsSnapshot(),
        )
        ctx = ScanContext(request=request)
        parent = ScanEvent(
            event_type="ip",
            value="8.8.8.8",
            source_module="seed",
            root_target="8.8.8.8",
        )

        payload = {"rdns": [{"name": "dns.google"}]}
        events = module._events_from_payload(payload, parent, ctx)
        event_types = [event.event_type for event in events]

        self.assertIn("co_hosted_site", event_types)
        self.assertIn("co_hosted_site_domain", event_types)


if __name__ == "__main__":
    unittest.main()
