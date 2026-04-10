from __future__ import annotations

import unittest

from python.cti_engine.context import ScanContext, ScanRequest
from python.cti_engine.events import ScanEvent
from python.cti_engine.modules.certspotter import CertSpotterModule
from python.cti_engine.settings import SettingsSnapshot
from python.cti_engine.targets import normalize_target


class CertSpotterModuleTests(unittest.TestCase):
    def test_payload_emits_certificate_summary_and_dns_names(self) -> None:
        module = CertSpotterModule()
        request = ScanRequest(
            scan_id=25,
            user_id=1,
            scan_name="CertSpotter Test",
            target=normalize_target("example.com", "domain"),
            selected_modules=["certspotter"],
            settings=SettingsSnapshot(
                module_settings={
                    "certspotter": {
                        "verify_alt_names": True,
                        "cert_expiry_days": 30,
                    }
                }
            ),
        )
        ctx = ScanContext(request=request)
        parent = ScanEvent(
            event_type="domain",
            value="example.com",
            source_module="seed",
            root_target="example.com",
        )

        payload = [
            {
                "dns_names": ["example.com", "www.example.com", "*.api.example.com"],
                "issuer": {"O": "Let's Encrypt"},
                "not_after": "2026-04-20T00:00:00+00:00",
            }
        ]

        events = module._events_from_payload(payload, parent, {"verify_alt_names": True, "cert_expiry_days": 30}, ctx)
        event_types = [event.event_type for event in events]
        self.assertIn("certificate_record", event_types)
        self.assertEqual(2, event_types.count("internet_name"))


if __name__ == "__main__":
    unittest.main()
