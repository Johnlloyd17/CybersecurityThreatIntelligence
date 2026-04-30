from __future__ import annotations

import unittest

from python.cti_engine.context import ScanContext, ScanRequest
from python.cti_engine.events import ScanEvent
from python.cti_engine.modules.passivedns import PassiveDnsModule
from python.cti_engine.settings import SettingsSnapshot
from python.cti_engine.targets import normalize_target


class PassiveDnsModuleTests(unittest.TestCase):
    def test_domain_records_emit_dns_rows_and_children(self) -> None:
        module = PassiveDnsModule()
        request = ScanRequest(
            scan_id=46,
            user_id=1,
            scan_name="Passive DNS Domain Test",
            target=normalize_target("example.com", "domain"),
            selected_modules=["passivedns"],
            settings=SettingsSnapshot(),
        )
        ctx = ScanContext(request=request)
        parent = ScanEvent(
            event_type="domain",
            value="example.com",
            source_module="seed",
            root_target="example.com",
        )

        records = [
            {"rrtype": "A", "rrvalue": "1.1.1.1", "source": "mnemonic"},
            {"rrtype": "NS", "rrvalue": "ns1.example.com", "source": "mnemonic"},
        ]
        events = module._events_from_records(records, parent, ctx)
        event_types = [event.event_type for event in events]

        self.assertIn("raw_dns_records", event_types)
        self.assertIn("ip", event_types)
        self.assertIn("internet_name", event_types)

    def test_ip_records_emit_cohosts(self) -> None:
        module = PassiveDnsModule()
        request = ScanRequest(
            scan_id=47,
            user_id=1,
            scan_name="Passive DNS IP Test",
            target=normalize_target("8.8.8.8", "ip"),
            selected_modules=["passivedns"],
            settings=SettingsSnapshot(),
        )
        ctx = ScanContext(request=request)
        parent = ScanEvent(
            event_type="ip",
            value="8.8.8.8",
            source_module="seed",
            root_target="8.8.8.8",
        )

        records = [{"rrtype": "PTR", "rrvalue": "dns.google", "source": "mnemonic"}]
        events = module._events_from_records(records, parent, ctx)
        event_types = [event.event_type for event in events]

        self.assertIn("co_hosted_site", event_types)
        self.assertIn("co_hosted_site_domain", event_types)


if __name__ == "__main__":
    unittest.main()
