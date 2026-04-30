from __future__ import annotations

import unittest

from python.cti_engine.context import ScanContext, ScanRequest
from python.cti_engine.events import ScanEvent
from python.cti_engine.modules.crtsh import CrtShModule
from python.cti_engine.settings import SettingsSnapshot
from python.cti_engine.targets import normalize_target


class CrtShModuleTests(unittest.TestCase):
    def test_payload_emits_spiderfoot_style_raw_and_host_events(self) -> None:
        module = CrtShModule()
        request = ScanRequest(
            scan_id=26,
            user_id=1,
            scan_name="crt.sh Test",
            target=normalize_target("example.com", "domain"),
            selected_modules=["crt-sh"],
            settings=SettingsSnapshot(),
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
                "common_name": "www.example.com",
                "name_value": "www.example.com\n*.dev.example.com\nexample.com",
                "issuer_name": "C=US, O=Example CA",
            }
        ]

        events = module._events_from_payload(
            payload,
            ["-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----"],
            parent,
            {"fetchcerts": True, "verify": False},
            ctx,
        )
        event_types = [event.event_type for event in events]
        self.assertIn("raw_rir_data", event_types)
        self.assertIn("ssl_certificate_raw", event_types)
        self.assertEqual(2, event_types.count("internet_name"))
        self.assertEqual(2, event_types.count("domain_name"))


if __name__ == "__main__":
    unittest.main()
