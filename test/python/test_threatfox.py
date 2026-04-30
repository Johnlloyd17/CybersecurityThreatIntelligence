from __future__ import annotations

import unittest

from python.cti_engine.context import ScanContext, ScanRequest
from python.cti_engine.events import ScanEvent
from python.cti_engine.modules.threatfox import ThreatFoxModule
from python.cti_engine.settings import SettingsSnapshot
from python.cti_engine.targets import normalize_target


class ThreatFoxModuleTests(unittest.TestCase):
    def test_ip_payload_emits_malicious_and_blacklisted_ip(self) -> None:
        module = ThreatFoxModule()
        request = ScanRequest(
            scan_id=31,
            user_id=1,
            scan_name="ThreatFox IP Test",
            target=normalize_target("8.8.8.8", "ip"),
            selected_modules=["threatfox"],
            settings=SettingsSnapshot(),
        )
        ctx = ScanContext(request=request)
        parent = ScanEvent(
            event_type="ip",
            value="8.8.8.8",
            source_module="seed",
            root_target="8.8.8.8",
        )
        payload = [
            {"malware": "TestMalware", "threat_type": "botnet_cc", "confidence_level": 85},
            {"malware": "TestMalware", "threat_type": "botnet_cc", "confidence_level": 90},
        ]
        events = module._events_from_payload(payload, parent, ctx)
        event_types = [event.event_type for event in events]
        self.assertIn("malicious_ip", event_types)
        self.assertIn("blacklisted_ip", event_types)
        self.assertNotIn("raw_rir_data", event_types)


if __name__ == "__main__":
    unittest.main()
