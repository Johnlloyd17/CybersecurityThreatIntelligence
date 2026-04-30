from __future__ import annotations

import unittest

from python.cti_engine.context import ScanContext, ScanRequest
from python.cti_engine.events import ScanEvent
from python.cti_engine.modules.abuseipdb import AbuseIpDbModule
from python.cti_engine.settings import SettingsSnapshot
from python.cti_engine.targets import normalize_target


class AbuseIpDbModuleTests(unittest.TestCase):
    def test_blacklist_parsing_emits_expected_events(self) -> None:
        module = AbuseIpDbModule()
        request = ScanRequest(
            scan_id=6,
            user_id=1,
            scan_name="AbuseIPDB Test",
            target=normalize_target("118.25.6.39", "ip"),
            selected_modules=["abuseipdb"],
            settings=SettingsSnapshot(),
        )
        ctx = ScanContext(request=request)
        parent = ScanEvent(
            event_type="ip",
            value="118.25.6.39",
            source_module="seed",
            root_target="118.25.6.39",
        )

        events = module._events_from_blacklist({"118.25.6.39", "203.0.113.10"}, parent, ctx)
        event_types = [event.event_type for event in events]
        self.assertIn("malicious_ip", event_types)
        self.assertIn("blacklisted_ip", event_types)

    def test_non_blacklisted_ip_emits_no_events(self) -> None:
        module = AbuseIpDbModule()
        request = ScanRequest(
            scan_id=7,
            user_id=1,
            scan_name="AbuseIPDB Clean Test",
            target=normalize_target("8.8.8.8", "ip"),
            selected_modules=["abuseipdb"],
            settings=SettingsSnapshot(),
        )
        ctx = ScanContext(request=request)
        parent = ScanEvent(
            event_type="ip",
            value="8.8.8.8",
            source_module="seed",
            root_target="8.8.8.8",
        )

        events = module._events_from_blacklist({"118.25.6.39"}, parent, ctx)
        self.assertEqual([], events)

    def test_parse_blacklist_ignores_comments(self) -> None:
        module = AbuseIpDbModule()
        blacklist = module._parse_blacklist("# Comment\n118.25.6.39\n\n203.0.113.10\n")
        self.assertEqual({"118.25.6.39", "203.0.113.10"}, blacklist)


if __name__ == "__main__":
    unittest.main()
