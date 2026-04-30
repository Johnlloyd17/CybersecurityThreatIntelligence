from __future__ import annotations

from datetime import datetime, timezone
import unittest
from unittest.mock import patch

from python.cti_engine.context import ScanContext, ScanRequest
from python.cti_engine.events import ScanEvent
from python.cti_engine.modules.certspotter import CertSpotterModule
from python.cti_engine.settings import SettingsSnapshot
from python.cti_engine.targets import normalize_target


class CertSpotterModuleTests(unittest.TestCase):
    def test_payload_emits_spiderfoot_style_certificate_and_host_events(self) -> None:
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
                        "verify": False,
                        "certexpiringdays": 30,
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
                "not_before": "2026-04-01T00:00:00+00:00",
                "not_after": "2026-04-20T00:00:00+00:00",
                "cert": {"data": "MIIBFAKECERT"},
            }
        ]

        with patch("python.cti_engine.modules.certspotter.datetime") as fake_datetime:
            fake_datetime.now.return_value = datetime(2026, 4, 10, tzinfo=timezone.utc)
            fake_datetime.fromisoformat.side_effect = datetime.fromisoformat
            fake_datetime.timezone = timezone
            events = module._events_from_payload(
                payload,
                parent,
                {"verify": False, "certexpiringdays": 30},
                ctx,
            )

        event_types = [event.event_type for event in events]
        self.assertIn("raw_rir_data", event_types)
        self.assertIn("ssl_certificate_raw", event_types)
        self.assertIn("ssl_certificate_issuer", event_types)
        self.assertIn("ssl_certificate_issued", event_types)
        self.assertIn("ssl_certificate_expiring", event_types)
        self.assertEqual(2, event_types.count("internet_name"))
        self.assertEqual(2, event_types.count("domain_name"))


if __name__ == "__main__":
    unittest.main()
