from __future__ import annotations

import unittest

from python.cti_engine.context import ScanContext, ScanRequest
from python.cti_engine.events import ScanEvent
from python.cti_engine.modules.securitytrails import SecurityTrailsModule
from python.cti_engine.settings import SettingsSnapshot
from python.cti_engine.targets import normalize_target


class SecurityTrailsModuleTests(unittest.TestCase):
    def test_domain_payload_emits_subdomains(self) -> None:
        module = SecurityTrailsModule()
        request = ScanRequest(
            scan_id=37,
            user_id=1,
            scan_name="SecurityTrails Domain Test",
            target=normalize_target("example.com", "domain"),
            selected_modules=["securitytrails"],
            settings=SettingsSnapshot(),
        )
        ctx = ScanContext(request=request)
        parent = ScanEvent(
            event_type="domain",
            value="example.com",
            source_module="seed",
            root_target="example.com",
        )
        events = module._events_from_domain_payload(["www", "mail"], parent, ctx)
        self.assertEqual(2, len(events))
        self.assertEqual("internet_name", events[0].event_type)

    def test_ip_payload_emits_cohost_and_provider(self) -> None:
        module = SecurityTrailsModule()
        request = ScanRequest(
            scan_id=38,
            user_id=1,
            scan_name="SecurityTrails IP Test",
            target=normalize_target("8.8.8.8", "ip"),
            selected_modules=["securitytrails"],
            settings=SettingsSnapshot(),
        )
        ctx = ScanContext(request=request)
        parent = ScanEvent(
            event_type="ip",
            value="8.8.8.8",
            source_module="seed",
            root_target="8.8.8.8",
        )
        payload = [{"host_provider": ["Google"], "hostname": "dns.google"}]
        events = module._events_from_ip_payload(payload, parent, ctx)
        event_types = [event.event_type for event in events]
        self.assertIn("provider_hosting", event_types)
        self.assertIn("co_hosted_site", event_types)

    def test_email_payload_emits_affiliate_domains(self) -> None:
        module = SecurityTrailsModule()
        request = ScanRequest(
            scan_id=39,
            user_id=1,
            scan_name="SecurityTrails Email Test",
            target=normalize_target("admin@example.com", "email"),
            selected_modules=["securitytrails"],
            settings=SettingsSnapshot(),
        )
        ctx = ScanContext(request=request)
        parent = ScanEvent(
            event_type="email",
            value="admin@example.com",
            source_module="seed",
            root_target="admin@example.com",
        )
        payload = [{"hostname": "related-one.com"}, {"hostname": "bad value"}]
        events = module._events_from_email_payload(payload, parent, ctx)
        event_types = [event.event_type for event in events]
        self.assertIn("affiliate_internet_name", event_types)
        self.assertIn("affiliate_domain_name", event_types)


if __name__ == "__main__":
    unittest.main()
