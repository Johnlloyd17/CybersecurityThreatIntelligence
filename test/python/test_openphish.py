from __future__ import annotations

import unittest

from python.cti_engine.context import ScanContext, ScanRequest
from python.cti_engine.events import ScanEvent
from python.cti_engine.modules.openphish import OpenPhishModule
from python.cti_engine.settings import SettingsSnapshot
from python.cti_engine.targets import normalize_target


class OpenPhishModuleTests(unittest.TestCase):
    def test_domain_feed_match_emits_malicious_and_blacklisted_events(self) -> None:
        module = OpenPhishModule()
        request = ScanRequest(
            scan_id=32,
            user_id=1,
            scan_name="OpenPhish Domain Test",
            target=normalize_target("bad.example", "domain"),
            selected_modules=["openphish"],
            settings=SettingsSnapshot(),
        )
        ctx = ScanContext(request=request)
        parent = ScanEvent(
            event_type="domain",
            value="bad.example",
            source_module="seed",
            root_target="bad.example",
        )
        events = module._events_from_feed({"bad.example"}, parent, ctx)
        event_types = [event.event_type for event in events]
        self.assertIn("malicious_internet_name", event_types)
        self.assertIn("blacklisted_internet_name", event_types)

    def test_url_feed_match_emits_malicious_url_and_hostname(self) -> None:
        module = OpenPhishModule()
        request = ScanRequest(
            scan_id=33,
            user_id=1,
            scan_name="OpenPhish URL Test",
            target=normalize_target("https://bad.example/login", "url"),
            selected_modules=["openphish"],
            settings=SettingsSnapshot(),
        )
        ctx = ScanContext(request=request)
        parent = ScanEvent(
            event_type="url",
            value="https://bad.example/login",
            source_module="seed",
            root_target="https://bad.example/login",
        )
        events = module._events_from_feed({"bad.example"}, parent, ctx)
        event_types = [event.event_type for event in events]
        self.assertIn("malicious_url", event_types)
        self.assertIn("internet_name", event_types)


if __name__ == "__main__":
    unittest.main()
