from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch

from python.cti_engine.context import ScanContext, ScanRequest
from python.cti_engine.events import ScanEvent
from python.cti_engine.modules.wave6_reputation import (
    AlienVaultIpRepModule,
    CleanTalkModule,
    CustomThreatFeedModule,
    FortiGuardModule,
    RetireJsModule,
    ScyllaModule,
    SnallygasterModule,
    SorbsModule,
    TalosIntelligenceModule,
)
from python.cti_engine.settings import SettingsSnapshot
from python.cti_engine.targets import normalize_target


def make_context(
    value: str,
    target_type: str,
    module_settings: dict[str, dict[str, object]] | None = None,
) -> ScanContext:
    return ScanContext(request=ScanRequest(
        scan_id=1460,
        user_id=1,
        scan_name="Wave 6 Test",
        target=normalize_target(value, target_type),
        selected_modules=[],
        settings=SettingsSnapshot(module_settings=module_settings or {}),
    ))


def make_parent(value: str, event_type: str, root_target: str | None = None) -> ScanEvent:
    return ScanEvent(
        event_type=event_type,
        value=value,
        source_module="seed",
        root_target=root_target or value,
    )


async def collect(module, parent: ScanEvent, ctx: ScanContext) -> list[ScanEvent]:
    return [child async for child in module.handle(parent, ctx)]


class WaveSixReputationModuleTests(unittest.TestCase):
    def test_alienvault_ip_rep_emits_malicious_ip_from_reputation_payload(self) -> None:
        module = AlienVaultIpRepModule()
        parent = make_parent("1.2.3.4", "ip")
        ctx = make_context("1.2.3.4", "ip")

        events = module._events_from_payload(
            {"reputation": 3, "reputation_details": [{"activity": "scanner"}]},
            parent,
            ctx,
        )

        self.assertEqual([("malicious_ip", "alienvault-ip-rep")], [(event.event_type, event.source_module) for event in events])

    def test_cleantalk_emits_blacklist_event_when_appears_positive(self) -> None:
        module = CleanTalkModule()
        parent = make_parent("1.2.3.4", "ip")
        ctx = make_context("1.2.3.4", "ip")

        events = module._events_from_payload({"data": {"1.2.3.4": {"appears": 1, "frequency": 12}}}, parent, ctx)

        self.assertEqual([("blacklisted_ip", "cleantalk")], [(event.event_type, event.source_module) for event in events])

    def test_custom_threat_feed_matches_indicator_line(self) -> None:
        module = CustomThreatFeedModule()
        parent = make_parent("evil.example", "domain")
        ctx = make_context("evil.example", "domain")

        events = module._events_from_content("good.example\nevil.example,malware\n", "https://feed.test/list.txt", "evil.example", parent, ctx)

        self.assertEqual([("blacklisted_indicator", "custom-threat-feed")], [(event.event_type, event.source_module) for event in events])

    def test_fortiguard_extracts_category(self) -> None:
        module = FortiGuardModule()
        parent = make_parent("example.com", "domain")
        ctx = make_context("example.com", "domain")

        events = module._events_from_body("Category: Phishing\n", "https://fortiguard.test", parent, ctx)

        self.assertEqual([("web_site_categorization", "example.com: Phishing")], [(event.event_type, event.value) for event in events])
        self.assertGreaterEqual(events[0].risk_score, 60)

    def test_scylla_emits_breach_record_from_payload(self) -> None:
        module = ScyllaModule()
        parent = make_parent("person@example.com", "email")
        ctx = make_context("person@example.com", "email")

        events = module._events_from_payload([{"domain": "breach.test"}], parent, ctx)

        self.assertEqual([("breach_record", "scylla")], [(event.event_type, event.source_module) for event in events])

    def test_sorbs_emits_dnsbl_events_from_result(self) -> None:
        module = SorbsModule()
        parent = make_parent("1.2.3.4", "ip")
        ctx = make_context("1.2.3.4", "ip")

        with patch.object(module, "_resolve", return_value=["127.0.0.2"]):
            events = asyncio.run(collect(module, parent, ctx))

        self.assertIn("blacklisted_ip", {event.event_type for event in events})

    def test_talos_emits_reputation_category(self) -> None:
        module = TalosIntelligenceModule()
        parent = make_parent("example.com", "domain")
        ctx = make_context("example.com", "domain")

        events = module._events_from_payload({"reputation": "Questionable", "category": ["Malware"]}, parent, ctx)

        self.assertEqual([("web_site_categorization", "talos-intelligence")], [(event.event_type, event.source_module) for event in events])
        self.assertGreaterEqual(events[0].risk_score, 60)

    def test_retire_js_detects_vulnerable_library(self) -> None:
        module = RetireJsModule()
        parent = make_parent("example.com", "domain")
        ctx = make_context("example.com", "domain")

        events = module._events_from_content('<script src="/js/jquery-1.8.3.js"></script>', "https://example.com", parent, ctx)

        self.assertEqual([("vulnerable_javascript_library", "retire-js")], [(event.event_type, event.source_module) for event in events])

    def test_snallygaster_emits_exposed_file_from_probe(self) -> None:
        module = SnallygasterModule()
        parent = make_parent("example.com", "domain")
        ctx = make_context("example.com", "domain")

        with patch(
            "python.cti_engine.modules.wave6_reputation._fetch_http",
            side_effect=[(200, "ref: refs/heads/main", "https://example.com/.git/HEAD", {})] + [(404, "", "", {})] * 20,
        ):
            events = asyncio.run(collect(module, parent, ctx))

        self.assertIn(("exposed_file", "snallygaster"), [(event.event_type, event.source_module) for event in events])


if __name__ == "__main__":
    unittest.main()
