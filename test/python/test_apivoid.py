from __future__ import annotations

import unittest

from python.cti_engine.context import ScanContext, ScanRequest
from python.cti_engine.events import ScanEvent
from python.cti_engine.modules.apivoid import ApiVoidModule
from python.cti_engine.settings import SettingsSnapshot
from python.cti_engine.targets import normalize_target


class ApiVoidModuleTests(unittest.TestCase):
    def test_ip_payload_emits_malicious_ip_and_reverse_dns(self) -> None:
        module = ApiVoidModule()
        request = ScanRequest(
            scan_id=12,
            user_id=1,
            scan_name="APIVoid IP Test",
            target=normalize_target("8.8.8.8", "ip"),
            selected_modules=["apivoid"],
            settings=SettingsSnapshot(module_settings={"apivoid": {"min_blacklist_detections": 1}}),
        )
        ctx = ScanContext(request=request)
        parent = ScanEvent(
            event_type="ip",
            value="8.8.8.8",
            source_module="seed",
            root_target="8.8.8.8",
        )

        payload = {
            "data": {
                "report": {
                    "blacklists": {"detection_rate": "3/42", "engines_count": 42},
                    "information": {"reverse_dns": "dns.google"},
                    "anonymity": {"is_proxy": False, "is_vpn": False, "is_tor": False},
                }
            }
        }

        events = module._events_from_payload(payload, parent, ctx, {"min_blacklist_detections": 1})
        event_types = [event.event_type for event in events]
        self.assertIn("malicious_ip", event_types)
        self.assertIn("internet_name", event_types)

    def test_domain_payload_emits_malicious_internet_name_and_server_ip(self) -> None:
        module = ApiVoidModule()
        request = ScanRequest(
            scan_id=13,
            user_id=1,
            scan_name="APIVoid Domain Test",
            target=normalize_target("example.com", "domain"),
            selected_modules=["apivoid"],
            settings=SettingsSnapshot(module_settings={"apivoid": {"min_blacklist_detections": 1}}),
        )
        ctx = ScanContext(request=request)
        parent = ScanEvent(
            event_type="domain",
            value="example.com",
            source_module="seed",
            root_target="example.com",
        )

        payload = {
            "data": {
                "report": {
                    "blacklists": {"detection_rate": "2/39"},
                    "server": {"ip": "93.184.216.34", "country_name": "US", "isp": "Example ISP"},
                }
            }
        }

        events = module._events_from_payload(payload, parent, ctx, {"min_blacklist_detections": 1})
        event_types = [event.event_type for event in events]
        self.assertIn("malicious_internet_name", event_types)
        self.assertIn("ip", event_types)

    def test_url_payload_emits_malicious_url_and_hostname(self) -> None:
        module = ApiVoidModule()
        request = ScanRequest(
            scan_id=14,
            user_id=1,
            scan_name="APIVoid URL Test",
            target=normalize_target("https://example.com/login", "url"),
            selected_modules=["apivoid"],
            settings=SettingsSnapshot(),
        )
        ctx = ScanContext(request=request)
        parent = ScanEvent(
            event_type="url",
            value="https://example.com/login",
            source_module="seed",
            root_target="https://example.com/login",
        )

        payload = {
            "data": {
                "report": {
                    "risk_score": {"result": 82},
                    "is_suspicious": True,
                    "response_headers": {"code": 200, "server": "nginx"},
                }
            }
        }

        events = module._events_from_payload(payload, parent, ctx, {})
        event_types = [event.event_type for event in events]
        self.assertIn("malicious_url", event_types)
        self.assertIn("internet_name", event_types)

    def test_email_payload_emits_email_event(self) -> None:
        module = ApiVoidModule()
        request = ScanRequest(
            scan_id=15,
            user_id=1,
            scan_name="APIVoid Email Test",
            target=normalize_target("analyst@example.com", "email"),
            selected_modules=["apivoid"],
            settings=SettingsSnapshot(),
        )
        ctx = ScanContext(request=request)
        parent = ScanEvent(
            event_type="email",
            value="analyst@example.com",
            source_module="seed",
            root_target="analyst@example.com",
        )

        payload = {
            "data": {
                "valid_format": True,
                "has_mx_records": True,
                "is_disposable": False,
                "is_suspicious_domain": False,
                "is_domain_blacklisted": False,
                "is_free": False,
                "domain_age_in_days": 3650,
            }
        }

        events = module._events_from_payload(payload, parent, ctx, {})
        self.assertEqual("email", events[0].event_type)
        self.assertEqual("analyst@example.com", events[0].value)


if __name__ == "__main__":
    unittest.main()
