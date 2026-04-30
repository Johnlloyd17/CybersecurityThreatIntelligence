from __future__ import annotations

from datetime import datetime, timezone
import unittest

from python.cti_engine.context import ScanContext, ScanRequest
from python.cti_engine.events import ScanEvent
from python.cti_engine.modules.wave1_osint import (
    ArchiveOrgModule,
    CommonCrawlModule,
    CrobatModule,
    HackerTargetModule,
    IscSansModule,
    MaltiverseModule,
    MnemonicPdnsModule,
    PhishStatsModule,
    RobtexModule,
    ThreatCrowdModule,
)
from python.cti_engine.settings import SettingsSnapshot
from python.cti_engine.targets import normalize_target


def make_context(
    value: str,
    target_type: str,
    module_settings: dict[str, dict[str, object]] | None = None,
) -> ScanContext:
    return ScanContext(request=ScanRequest(
        scan_id=777,
        user_id=1,
        scan_name="Wave 1 Test",
        target=normalize_target(value, target_type),
        selected_modules=[],
        settings=SettingsSnapshot(module_settings=module_settings or {}),
    ))


def make_parent(value: str, event_type: str) -> ScanEvent:
    return ScanEvent(
        event_type=event_type,
        value=value,
        source_module="seed",
        root_target=value,
    )


class WaveOneOsintModuleTests(unittest.TestCase):
    def test_commoncrawl_filters_to_root_target_urls(self) -> None:
        module = CommonCrawlModule()
        parent = make_parent("example.com", "domain")
        ctx = make_context("example.com", "domain")

        events = module._events_from_records(
            [
                {"url": "https://www.example.com/a"},
                {"url": "https://api.example.com/b"},
                {"url": "https://not-example.net/c"},
            ],
            parent,
            ctx,
        )

        self.assertEqual({"linked_url_internal"}, {event.event_type for event in events})
        self.assertEqual(2, len(events))

    def test_archiveorg_maps_to_historic_event_types(self) -> None:
        module = ArchiveOrgModule()
        parent = make_parent("https://example.com/login", "url_password")
        ctx = make_context("https://example.com/login", "url")

        events = module._events_from_snapshot(
            {
                "archived_snapshots": {
                    "closest": {
                        "available": True,
                        "url": "https://web.archive.org/web/20260401/https://example.com/login",
                    }
                }
            },
            parent,
            ctx,
        )

        self.assertEqual(["url_password_historic"], [event.event_type for event in events])

    def test_archiveorg_deduplicates_same_snapshot_across_days(self) -> None:
        module = ArchiveOrgModule()
        parent = make_parent("https://example.com/login", "url_password")
        ctx = make_context("https://example.com/login", "url")

        events_one = module._events_from_snapshot(
            {
                "archived_snapshots": {
                    "closest": {
                        "available": True,
                        "url": "https://web.archive.org/web/20260401/https://example.com/login",
                    }
                }
            },
            parent,
            ctx,
        )
        events_two = module._events_from_snapshot(
            {
                "archived_snapshots": {
                    "closest": {
                        "available": True,
                        "url": "https://web.archive.org/web/20260401/https://example.com/login",
                    }
                }
            },
            parent,
            ctx,
        )

        self.assertEqual(events_one[0].value, events_two[0].value)

    def test_crobat_emits_resolved_and_unresolved_subdomains(self) -> None:
        module = CrobatModule()
        parent = make_parent("example.com", "domain")
        ctx = make_context("example.com", "domain", {"crobat": {"dns_resolve": False}})

        events = module._events_from_page_payload(["api.example.com", "cdn.example.com"], parent, ctx)

        event_types = {event.event_type for event in events}
        self.assertIn("raw_rir_data", event_types)
        self.assertIn("internet_name", event_types)

    def test_hackertarget_domain_parser_emits_hosts_and_ips(self) -> None:
        module = HackerTargetModule()
        parent = make_parent("example.com", "domain")
        ctx = make_context("example.com", "domain")

        events = module._events_from_hostsearch(
            "www.example.com,93.184.216.34\napi.example.com,93.184.216.35\n",
            parent,
            ctx,
        )

        event_types = {event.event_type for event in events}
        self.assertIn("raw_dns_records", event_types)
        self.assertIn("internet_name", event_types)
        self.assertIn("ip", event_types)

    def test_isc_sans_positive_payload_emits_ip_pair(self) -> None:
        module = IscSansModule()
        parent = make_parent("1.2.3.4", "ip")
        ctx = make_context("1.2.3.4", "ip")

        events = module._events_from_payload({"ip": {"attacks": 12, "count": 5}}, parent, ctx)

        self.assertEqual({"malicious_ip", "blacklisted_ip"}, {event.event_type for event in events})

    def test_mnemonic_domain_records_emit_verified_or_unresolved_host(self) -> None:
        module = MnemonicPdnsModule()
        parent = make_parent("example.com", "domain")
        ctx = make_context("example.com", "domain")
        fresh_ts = int(datetime.now(timezone.utc).timestamp() * 1000)

        events = module._events_from_records(
            [{"query": "api.example.com", "answer": "example.com", "rrtype": "CNAME", "lastSeenTimestamp": fresh_ts}],
            parent,
            ctx,
        )

        event_types = {event.event_type for event in events}
        self.assertIn("internet_name_unresolved", event_types)
        self.assertIn("domain_name", event_types)

    def test_phishstats_ip_match_emits_malicious_and_blacklisted_ip(self) -> None:
        module = PhishStatsModule()
        parent = make_parent("1.2.3.4", "ip")
        ctx = make_context("1.2.3.4", "ip")

        events = module._events_from_payload(
            [{"ip": "1.2.3.4", "url": "https://phish.example/login"}],
            parent,
            ctx,
        )

        event_types = {event.event_type for event in events}
        self.assertIn("malicious_ip", event_types)
        self.assertIn("blacklisted_ip", event_types)
        self.assertIn("malicious_url", event_types)

    def test_robtex_ip_payload_emits_cohost_events(self) -> None:
        module = RobtexModule()
        parent = make_parent("8.8.8.8", "ip")
        ctx = make_context("8.8.8.8", "ip", {"robtex": {"verify": False}})

        events = module._events_from_ip_payload(
            {"pas": [{"o": "mail.example.com"}]},
            parent,
            ctx,
        )

        event_types = {event.event_type for event in events}
        self.assertIn("raw_rir_data", event_types)
        self.assertIn("co_hosted_site", event_types)
        self.assertNotIn("co_hosted_site_domain", event_types)

    def test_threatcrowd_negative_votes_emit_only_malicious_domain_pair(self) -> None:
        module = ThreatCrowdModule()
        parent = make_parent("example.com", "domain")
        ctx = make_context("example.com", "domain")

        events = module._events_from_payload(
            {
                "votes": -3,
                "permalink": "https://www.threatcrowd.org/domain.php?domain=example.com",
                "subdomains": ["api.example.com"],
                "resolutions": [{"ip_address": "1.2.3.4"}],
                "hashes": ["0123456789abcdef0123456789abcdef"],
                "emails": ["abuse@example.com"],
            },
            parent,
            ctx,
        )

        event_types = {event.event_type for event in events}
        self.assertIn("malicious_internet_name", event_types)
        self.assertIn("blacklisted_internet_name", event_types)
        self.assertEqual(2, len(events))

    def test_maltiverse_blacklist_payload_emits_source_like_malicious_ip(self) -> None:
        module = MaltiverseModule()
        parent = make_parent("8.8.8.8", "ip")
        ctx = make_context("8.8.8.8", "ip")

        events = module._events_from_payload(
            {
                "ip_addr": "8.8.8.8",
                "blacklist": [
                    {"source": "x", "description": "Known malicious host", "last_seen": "2026-04-20 00:00:00"}
                ],
            },
            parent,
            ctx,
        )

        event_types = {event.event_type for event in events}
        self.assertIn("raw_rir_data", event_types)
        self.assertIn("malicious_ip", event_types)
        self.assertNotIn("blacklisted_ip", event_types)


if __name__ == "__main__":
    unittest.main()
