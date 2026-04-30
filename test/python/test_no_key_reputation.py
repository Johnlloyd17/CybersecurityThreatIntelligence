from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import unittest

from python.cti_engine.context import ScanContext, ScanRequest
from python.cti_engine.events import ScanEvent
from python.cti_engine.modules.no_key_reputation import (
    AdBlockCheckModule,
    Base64DecoderModule,
    BlocklistDeModule,
    BotvrijModule,
    CinsScoreModule,
    CoinBlockerModule,
    CyberCrimeTrackerModule,
    DroneBlModule,
    EmergingThreatsModule,
    GreenSnowModule,
    MultiProxyModule,
    SpamCopModule,
    SpamHausZenModule,
    StevenBlackHostsModule,
    SurblModule,
    ThreatMinerModule,
    TorExitNodesModule,
    VxVaultModule,
    ZoneHModule,
)
from python.cti_engine.settings import SettingsSnapshot
from python.cti_engine.targets import normalize_target


def make_context(
    value: str,
    target_type: str,
    module_settings: dict[str, dict[str, object]] | None = None,
) -> ScanContext:
    return ScanContext(request=ScanRequest(
        scan_id=501,
        user_id=1,
        scan_name="No Key Module Test",
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


async def collect(module, event: ScanEvent, ctx: ScanContext) -> list[ScanEvent]:
    return [child async for child in module.handle(event, ctx)]


class NoKeyReputationModuleTests(unittest.TestCase):
    def test_blocklistde_feed_match_emits_malicious_and_blacklisted_ip(self) -> None:
        module = BlocklistDeModule()
        ctx = make_context("1.2.3.4", "ip")
        parent = make_parent("1.2.3.4", "ip")

        events = module._events_from_feed("# comment\n1.2.3.4\n", parent, ctx)
        event_types = {event.event_type for event in events}

        self.assertEqual({"malicious_ip", "blacklisted_ip"}, event_types)
        self.assertTrue(all("blocklist.de [1.2.3.4]" in event.value for event in events))

    def test_blocklistde_netblock_match_emits_netblock_events(self) -> None:
        module = BlocklistDeModule()
        ctx = make_context("1.2.3.0/24", "domain")
        parent = make_parent("1.2.3.0/24", "netblock_ownership")

        events = module._events_from_feed("# comment\n1.2.3.4\n", parent, ctx)
        event_types = {event.event_type for event in events}

        self.assertEqual({"malicious_netblock", "blacklisted_netblock"}, event_types)
        self.assertTrue(all("blocklist.de [1.2.3.0/24]" in event.value for event in events))

    def test_domain_feed_parsers_follow_spiderfoot_sources(self) -> None:
        botvrij = BotvrijModule()
        coinblocker = CoinBlockerModule()
        stevenblack = StevenBlackHostsModule()

        self.assertIn("bad.example", botvrij._parse_feed("bad.example,malware\n"))
        self.assertIn("miner.example", coinblocker._parse_feed("# x\nminer.example\n"))
        self.assertIn("ads.example", stevenblack._parse_feed("0.0.0.0 ads.example\n"))

    def test_batch_one_watched_types_match_spiderfoot_expectations(self) -> None:
        self.assertEqual({"ip", "ipv6", "affiliate_ipaddr", "netblock_ownership"}, BlocklistDeModule.watched_types)
        self.assertEqual({"ip", "affiliate_ipaddr", "netblock_ownership"}, CinsScoreModule.watched_types)
        self.assertEqual({"ip", "affiliate_ipaddr", "netblock_ownership"}, EmergingThreatsModule.watched_types)
        self.assertEqual({"ip", "affiliate_ipaddr", "netblock_ownership"}, GreenSnowModule.watched_types)
        self.assertEqual({"domain", "internet_name", "affiliate_internet_name", "co_hosted_site"}, BotvrijModule.watched_types)
        self.assertEqual({"domain", "internet_name", "affiliate_internet_name", "co_hosted_site"}, CoinBlockerModule.watched_types)
        self.assertEqual({"domain", "internet_name", "ip", "affiliate_internet_name", "affiliate_ipaddr", "co_hosted_site"}, CyberCrimeTrackerModule.watched_types)
        self.assertEqual({"ip", "affiliate_ipaddr", "netblock_ownership"}, DroneBlModule.watched_types)
        self.assertEqual({"linked_url_internal", "linked_url_external", "provider_javascript"}, AdBlockCheckModule.watched_types)
        self.assertEqual({"linked_url_internal"}, Base64DecoderModule.watched_types)

    def test_batch_two_watched_types_match_spiderfoot_expectations(self) -> None:
        self.assertEqual({"ip", "affiliate_ipaddr", "netblock_ownership"}, MultiProxyModule.watched_types)
        self.assertEqual({"ip", "affiliate_ipaddr", "netblock_ownership", "netblock_member"}, SpamCopModule.watched_types)
        self.assertEqual({"ip", "affiliate_ipaddr", "netblock_ownership", "netblock_member"}, SpamHausZenModule.watched_types)
        self.assertEqual({"domain", "internet_name", "affiliate_internet_name", "co_hosted_site"}, StevenBlackHostsModule.watched_types)
        self.assertEqual(
            {"domain", "internet_name", "ip", "affiliate_ipaddr", "netblock_ownership", "netblock_member", "affiliate_internet_name", "co_hosted_site"},
            SurblModule.watched_types,
        )
        self.assertEqual({"domain", "ip", "netblock_ownership", "netblock_member"}, ThreatMinerModule.watched_types)
        self.assertEqual({"ip", "ipv6", "affiliate_ipaddr", "netblock_ownership"}, TorExitNodesModule.watched_types)
        self.assertEqual({"domain", "internet_name", "ip", "ipv6", "affiliate_internet_name", "affiliate_ipaddr", "co_hosted_site"}, VxVaultModule.watched_types)
        self.assertEqual({"domain", "internet_name", "ip", "ipv6", "affiliate_internet_name", "affiliate_ipaddr", "co_hosted_site"}, ZoneHModule.watched_types)

    def test_indicator_modules_emit_affiliate_and_cohost_pairs(self) -> None:
        ctx = make_context("bad.example", "domain")

        botvrij_events = BotvrijModule()._events_from_feed(
            "bad.example,malware\n",
            make_parent("bad.example", "affiliate_internet_name"),
            ctx,
        )
        self.assertEqual(
            {"malicious_affiliate_internet_name", "blacklisted_affiliate_internet_name"},
            {event.event_type for event in botvrij_events},
        )

        coinblocker_events = CoinBlockerModule()._events_from_feed(
            "bad.example\n",
            make_parent("bad.example", "co_hosted_site"),
            ctx,
        )
        self.assertEqual(
            {"malicious_cohost", "blacklisted_cohost"},
            {event.event_type for event in coinblocker_events},
        )

        cybercrime_events = CyberCrimeTrackerModule()._events_from_feed(
            "1.2.3.4/path\n",
            make_parent("1.2.3.4", "affiliate_ipaddr"),
            make_context("1.2.3.4", "ip"),
        )
        self.assertEqual(
            {"malicious_affiliate_ipaddr", "blacklisted_affiliate_ipaddr"},
            {event.event_type for event in cybercrime_events},
        )

    def test_spamhaus_dnsbl_code_emits_spiderfoot_pair(self) -> None:
        module = SpamHausZenModule()
        module._resolve = lambda _lookup: ["127.0.0.2"]  # type: ignore[method-assign]
        ctx = make_context("1.2.3.4", "ip")
        parent = make_parent("1.2.3.4", "ip")

        events = asyncio.run(collect(module, parent, ctx))
        event_types = {event.event_type for event in events}

        self.assertEqual({"malicious_ip", "blacklisted_ip"}, event_types)
        self.assertTrue(any("Spamhaus (Zen) - Spammer" in event.value for event in events))

    def test_spamhaus_affiliate_ip_emits_affiliate_pair(self) -> None:
        module = SpamHausZenModule()
        module._resolve = lambda _lookup: ["127.0.0.2"]  # type: ignore[method-assign]
        ctx = make_context("1.2.3.4", "ip")
        parent = make_parent("1.2.3.4", "affiliate_ipaddr")

        events = asyncio.run(collect(module, parent, ctx))

        self.assertEqual(
            {"malicious_affiliate_ipaddr", "blacklisted_affiliate_ipaddr"},
            {event.event_type for event in events},
        )

    def test_spamcop_netblock_lookup_emits_netblock_pair(self) -> None:
        module = SpamCopModule()
        module._resolve = lambda _lookup: ["127.0.0.2"]  # type: ignore[method-assign]
        ctx = make_context("1.2.3.4/32", "ip")
        parent = make_parent("1.2.3.4/32", "netblock_ownership")

        events = asyncio.run(collect(module, parent, ctx))

        self.assertEqual({"malicious_netblock", "blacklisted_netblock"}, {event.event_type for event in events})
        self.assertTrue(all("[1.2.3.4]" in event.value for event in events))

    def test_dronebl_proxy_code_emits_proxy_host_without_malicious_ip(self) -> None:
        module = DroneBlModule()
        module._resolve = lambda _lookup: ["127.0.0.8"]  # type: ignore[method-assign]
        ctx = make_context("1.2.3.4", "ip")
        parent = make_parent("1.2.3.4", "ip")

        events = asyncio.run(collect(module, parent, ctx))
        event_types = {event.event_type for event in events}

        self.assertIn("blacklisted_ip", event_types)
        self.assertIn("proxy_host", event_types)
        self.assertNotIn("malicious_ip", event_types)

    def test_tor_exit_node_parser_matches_or_and_exit_addresses(self) -> None:
        module = TorExitNodesModule()
        payload = {
            "relays": [{
                "or_addresses": ["1.2.3.4:9001", "[2001:db8::1]:9001"],
                "exit_addresses": ["5.6.7.8"],
            }]
        }

        addresses = module._parse_exit_nodes(json.dumps(payload))

        self.assertIn("1.2.3.4", addresses)
        self.assertIn("2001:db8::1", addresses)
        self.assertIn("5.6.7.8", addresses)

    def test_tor_exit_nodes_netblock_emits_ip_then_tor_event(self) -> None:
        module = TorExitNodesModule()
        from python.cti_engine.modules import no_key_reputation as no_key_module

        original_fetch = no_key_module._fetch_text
        try:
            no_key_module._fetch_text = lambda url, timeout, ctx, slug, accept="text/plain, */*": '{"relays":[]}'  # type: ignore[assignment]
            module._parse_exit_nodes = lambda _content: {"1.2.3.1"}  # type: ignore[method-assign]
            ctx = make_context("1.2.3.0/30", "ip")
            parent = make_parent("1.2.3.0/30", "netblock_ownership")
            events = asyncio.run(collect(module, parent, ctx))
        finally:
            no_key_module._fetch_text = original_fetch  # type: ignore[assignment]

        self.assertEqual(["ip", "tor_exit_node"], [event.event_type for event in events])
        self.assertEqual(events[0].event_id, events[1].parent_event_id)

    def test_base64_decoder_emits_decoded_data(self) -> None:
        module = Base64DecoderModule()
        ctx = make_context("https://example.com/?q=U2VjcmV0VGVzdA==", "url")
        parent = make_parent("https://example.com/?q=U2VjcmV0VGVzdA==", "linked_url_internal")

        events = asyncio.run(collect(module, parent, ctx))

        self.assertEqual(["base64_data"], [event.event_type for event in events])
        self.assertIn("SecretTest", events[0].value)

    def test_base64_decoder_ignores_direct_root_url_like_spiderfoot(self) -> None:
        module = Base64DecoderModule()
        ctx = make_context("https://example.com/?q=U2VjcmV0VGVzdA==", "url")
        parent = make_parent("https://example.com/?q=U2VjcmV0VGVzdA==", "url")

        events = asyncio.run(collect(module, parent, ctx))

        self.assertEqual([], events)

    def test_adblock_fallback_matches_easylist_domain_rule(self) -> None:
        module = AdBlockCheckModule()
        ctx = make_context("ads.example", "domain")
        rules = module._rules_from_content("! comment\n||ads.example^\n", ctx)

        self.assertTrue(rules.should_block("http://ads.example/"))
        self.assertTrue(rules.should_block("http://cdn.ads.example/banner.js"))

    def test_adblock_emits_internal_and_external_events_like_spiderfoot(self) -> None:
        module = AdBlockCheckModule()
        from python.cti_engine.modules import no_key_reputation as no_key_module

        original_fetch = no_key_module._fetch_text
        try:
            no_key_module._fetch_text = lambda url, timeout, ctx, slug, accept="text/plain, */*": "||ads.example^\n"  # type: ignore[assignment]
            ctx = make_context("ads.example", "domain")
            internal = asyncio.run(collect(module, make_parent("http://ads.example/", "linked_url_internal"), ctx))
            external = asyncio.run(collect(module, make_parent("http://ads.example/", "linked_url_external"), ctx))
            script = asyncio.run(collect(module, make_parent("http://ads.example/script.js", "provider_javascript"), ctx))
        finally:
            no_key_module._fetch_text = original_fetch  # type: ignore[assignment]

        self.assertEqual(["url_adblocked_internal"], [event.event_type for event in internal])
        self.assertEqual(["url_adblocked_external"], [event.event_type for event in external])
        self.assertEqual(["url_adblocked_external"], [event.event_type for event in script])

    def test_adblock_reads_blocklist_url_setting_name_used_by_cti(self) -> None:
        module = AdBlockCheckModule()
        calls: list[str] = []

        def fake_rules(_content: str, _ctx):
            class AlwaysBlock:
                def should_block(self, _url: str, _options=None) -> bool:
                    return True
            return AlwaysBlock()

        module._rules_from_content = fake_rules  # type: ignore[method-assign]

        from python.cti_engine.modules import no_key_reputation as no_key_module

        original_fetch = no_key_module._fetch_text
        try:
            no_key_module._fetch_text = lambda url, timeout, ctx, slug, accept="text/plain, */*": calls.append(url) or "||ads.example^\n"  # type: ignore[assignment]
            ctx = make_context(
                "ads.example",
                "domain",
                module_settings={"adblock-check": {"blocklist_url": "https://example.invalid/easylist.txt"}},
            )
            events = asyncio.run(collect(module, make_parent("http://ads.example/", "linked_url_internal"), ctx))
        finally:
            no_key_module._fetch_text = original_fetch  # type: ignore[assignment]

        self.assertEqual(["https://example.invalid/easylist.txt"], calls)
        self.assertEqual(["url_adblocked_internal"], [event.event_type for event in events])

    def test_zoneh_lookup_returns_spiderfoot_value(self) -> None:
        module = ZoneHModule()
        content = (
            "<title><![CDATA[defaced bad.example]]></title>\n"
            "<link><![CDATA[https://zone-h.org/mirror/id/1]]></link>"
        )

        value = module._lookup_item("bad.example", content)

        self.assertEqual("defaced bad.example\n<SFURL>https://zone-h.org/mirror/id/1</SFURL>", value)

    def test_zoneh_emits_cohost_type(self) -> None:
        module = ZoneHModule()
        from python.cti_engine.modules import no_key_reputation as no_key_module

        original_fetch = no_key_module._fetch_text
        try:
            no_key_module._fetch_text = lambda url, timeout, ctx, slug, accept="text/plain, */*": (  # type: ignore[assignment]
                "<title><![CDATA[defaced bad.example]]></title>\n"
                "<link><![CDATA[https://zone-h.org/mirror/id/1]]></link>"
            )
            ctx = make_context("bad.example", "domain")
            events = asyncio.run(collect(module, make_parent("bad.example", "co_hosted_site"), ctx))
        finally:
            no_key_module._fetch_text = original_fetch  # type: ignore[assignment]

        self.assertEqual(["defaced_cohost"], [event.event_type for event in events])

    def test_threatminer_domain_payload_emits_internet_names(self) -> None:
        module = ThreatMinerModule()
        ctx = make_context("example.com", "domain")
        parent = make_parent("example.com", "domain")

        events = module._domain_events({"results": ["a.example.com", "a.example.com"]}, parent, ctx)

        self.assertEqual(1, len(events))
        self.assertEqual("internet_name", events[0].event_type)
        self.assertEqual("a.example.com", events[0].value)

    def test_threatminer_ip_payload_distinguishes_root_hosts_and_cohosts(self) -> None:
        module = ThreatMinerModule()
        ctx = make_context("example.com", "domain")
        parent = make_parent("1.2.3.4", "ip")
        fresh = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        events = module._ip_events(
            {
                "results": [
                    {"domain": "mail.example.com", "last_seen": fresh},
                    {"domain": "elsewhere.test", "last_seen": fresh},
                ]
            },
            parent,
            ctx,
            verify=False,
            max_cohosts=100,
            age_limit_days=90,
        )

        self.assertEqual(["internet_name", "co_hosted_site"], [event.event_type for event in events])
        self.assertEqual("mail.example.com", events[0].value)
        self.assertEqual("elsewhere.test", events[1].value)

    def test_threatminer_age_limit_zero_keeps_old_records(self) -> None:
        module = ThreatMinerModule()
        self.assertFalse(module._is_too_old("2001-01-01 00:00:00", 0))

    def test_multiproxy_netblock_is_disabled_by_default_like_spiderfoot(self) -> None:
        module = MultiProxyModule()
        from python.cti_engine.modules import no_key_reputation as no_key_module

        original_fetch = no_key_module._fetch_text
        try:
            no_key_module._fetch_text = lambda url, timeout, ctx, slug, accept="text/plain, */*": "1.2.3.4:8080\n"  # type: ignore[assignment]
            ctx = make_context("1.2.3.0/24", "ip")
            events = asyncio.run(collect(module, make_parent("1.2.3.0/24", "netblock_ownership"), ctx))
        finally:
            no_key_module._fetch_text = original_fetch  # type: ignore[assignment]

        self.assertEqual([], events)

    def test_multiproxy_netblock_can_be_enabled_explicitly(self) -> None:
        module = MultiProxyModule()
        from python.cti_engine.modules import no_key_reputation as no_key_module

        original_fetch = no_key_module._fetch_text
        try:
            no_key_module._fetch_text = lambda url, timeout, ctx, slug, accept="text/plain, */*": "1.2.3.4:8080\n"  # type: ignore[assignment]
            ctx = make_context("1.2.3.0/24", "ip", module_settings={"multiproxy": {"netblocklookup": True}})
            events = asyncio.run(collect(module, make_parent("1.2.3.0/24", "netblock_ownership"), ctx))
        finally:
            no_key_module._fetch_text = original_fetch  # type: ignore[assignment]

        self.assertEqual({"malicious_netblock", "blacklisted_netblock"}, {event.event_type for event in events})

    def test_surbl_cohost_emits_spiderfoot_pair(self) -> None:
        module = SurblModule()
        module._resolve = lambda _lookup: ["127.0.0.2"]  # type: ignore[method-assign]
        ctx = make_context("bad.example", "domain")
        events = asyncio.run(collect(module, make_parent("bad.example", "co_hosted_site"), ctx))

        self.assertEqual({"malicious_cohost", "blacklisted_cohost"}, {event.event_type for event in events})

    def test_vxvault_feed_matches_domain_or_ip_host_indicator(self) -> None:
        module = VxVaultModule()
        ctx = make_context("bad.example", "domain")
        parent = make_parent("bad.example", "domain")

        events = module._events_from_feed("http://bad.example/other.exe\n", parent, ctx)

        self.assertEqual(["malicious_internet_name"], [event.event_type for event in events])
        self.assertIn("VXVault Malicious URL List", events[0].value)

        affiliate_events = module._events_from_feed(
            "http://1.2.3.4/payload.exe\n",
            make_parent("1.2.3.4", "affiliate_ipaddr"),
            make_context("1.2.3.4", "ip"),
        )
        self.assertEqual(["malicious_affiliate_ipaddr"], [event.event_type for event in affiliate_events])


if __name__ == "__main__":
    unittest.main()
