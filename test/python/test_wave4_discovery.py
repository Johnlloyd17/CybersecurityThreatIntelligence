from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch

from python.cti_engine.context import ScanContext, ScanRequest
from python.cti_engine.events import ScanEvent
from python.cti_engine.modules.wave4_discovery import (
    OPENNIC_NAMESERVERS,
    AzureBlobFinderModule,
    DnsLookasideModule,
    DnsTwistModule,
    DnsZoneTransferModule,
    DoSpaceFinderModule,
    GcsFinderModule,
    OpenNicModule,
    OpenPdnsModule,
    S3FinderModule,
    WebSpiderModule,
)
from python.cti_engine.settings import SettingsSnapshot
from python.cti_engine.targets import normalize_target


def make_context(
    value: str,
    target_type: str,
    module_settings: dict[str, dict[str, object]] | None = None,
) -> ScanContext:
    return ScanContext(request=ScanRequest(
        scan_id=780,
        user_id=1,
        scan_name="Wave 4 Test",
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


async def collect(module, parent: ScanEvent, ctx: ScanContext) -> list[ScanEvent]:
    return [child async for child in module.handle(parent, ctx)]


class WaveFourDiscoveryModuleTests(unittest.TestCase):
    def test_azure_blob_treats_any_http_response_as_existing_account_like_spiderfoot(self) -> None:
        module = AzureBlobFinderModule()
        parent = make_parent("example.com", "domain")
        ctx = make_context("example.com", "domain")

        events = module._events_from_probe_results(
            [
                ("https://example.blob.core.windows.net", 400, "", "https://example.blob.core.windows.net", {}),
                ("https://missing.blob.core.windows.net", 404, "", "https://missing.blob.core.windows.net", {}),
            ],
            parent,
            ctx,
        )

        self.assertEqual(["cloud_storage_bucket", "cloud_storage_bucket"], [event.event_type for event in events])
        self.assertEqual(
            {"https://example.blob.core.windows.net", "https://missing.blob.core.windows.net"},
            {event.value for event in events},
        )

    def test_do_space_emits_bucket_and_open_bucket_events(self) -> None:
        module = DoSpaceFinderModule()
        parent = make_parent("example.com", "domain")
        ctx = make_context("example.com", "domain")

        events = module._events_from_probe_results(
            [
                (
                    "https://example.nyc3.digitaloceanspaces.com",
                    200,
                    "<ListBucketResult><Key>a</Key><Key>b</Key></ListBucketResult>",
                    "https://example.nyc3.digitaloceanspaces.com",
                    {},
                )
            ],
            parent,
            ctx,
        )

        self.assertEqual(
            {"cloud_storage_bucket", "cloud_storage_bucket_open"},
            {event.event_type for event in events},
        )
        self.assertIn(
            "https://example.nyc3.digitaloceanspaces.com",
            [event.value for event in events if event.event_type == "cloud_storage_bucket"],
        )
        self.assertIn(
            "https://example.nyc3.digitaloceanspaces.com: 2 files found.",
            [event.value for event in events if event.event_type == "cloud_storage_bucket_open"],
        )

    def test_gcs_emits_bucket_and_open_bucket_events(self) -> None:
        module = GcsFinderModule()
        parent = make_parent("example.com", "domain")
        ctx = make_context("example.com", "domain")

        events = module._events_from_probe_results(
            [
                (
                    "https://example.storage.googleapis.com",
                    301,
                    "<ListBucketResult><Key>a</Key></ListBucketResult>",
                    "https://example.storage.googleapis.com",
                    {},
                )
            ],
            parent,
            ctx,
        )

        self.assertEqual(
            {"cloud_storage_bucket", "cloud_storage_bucket_open"},
            {event.event_type for event in events},
        )
        self.assertIn(
            "https://example.storage.googleapis.com",
            [event.value for event in events if event.event_type == "cloud_storage_bucket"],
        )
        self.assertIn(
            "example.storage.googleapis.com: 1 files found.",
            [event.value for event in events if event.event_type == "cloud_storage_bucket_open"],
        )

    def test_s3_emits_bucket_and_open_bucket_events(self) -> None:
        module = S3FinderModule()
        parent = make_parent("example.com", "domain")
        ctx = make_context("example.com", "domain")

        events = module._events_from_probe_results(
            [
                (
                    "https://example.s3.amazonaws.com",
                    200,
                    "<ListBucketResult><Key>a</Key><Key>b</Key></ListBucketResult>",
                    "https://example.s3.amazonaws.com",
                    {},
                )
            ],
            parent,
            ctx,
        )

        self.assertEqual(
            {"cloud_storage_bucket", "cloud_storage_bucket_open"},
            {event.event_type for event in events},
        )
        self.assertIn("https://example.s3.amazonaws.com", [event.value for event in events if event.event_type == "cloud_storage_bucket"])
        self.assertIn("example.s3.amazonaws.com: 2 files found.", [event.value for event in events if event.event_type == "cloud_storage_bucket_open"])

    def test_dns_lookaside_classifies_related_and_affiliate_ips(self) -> None:
        module = DnsLookasideModule()
        parent = make_parent("example.com", "domain")
        ctx = make_context("example.com", "domain")

        events = module._events_from_reverse_map(
            {
                "1.2.3.5": ["api.example.com"],
                "1.2.3.6": ["mail.other.net"],
            },
            parent,
            ctx,
        )

        event_pairs = {(event.event_type, event.value) for event in events}
        self.assertIn(("ip", "1.2.3.5"), event_pairs)
        self.assertIn(("affiliate_ipaddr", "1.2.3.6"), event_pairs)

    def test_dns_zone_transfer_emits_raw_records_and_hosts(self) -> None:
        module = DnsZoneTransferModule()
        parent = make_parent("example.com", "domain")
        ctx = make_context("example.com", "domain")

        events = module._events_from_transfer_records(
            [
                {"name": "www", "type": "A", "ttl": 300, "text": "1.2.3.4"},
                {"name": "api.example.com", "type": "CNAME", "ttl": 300, "text": "example.com"},
            ],
            parent,
            ctx,
        )

        event_types = {event.event_type for event in events}
        self.assertIn("raw_dns_records", event_types)
        self.assertIn("internet_name", event_types)
        self.assertIn("www.example.com", [event.value for event in events if event.event_type == "internet_name"])

    def test_dnstwist_emits_only_other_registered_domains(self) -> None:
        module = DnsTwistModule()
        parent = make_parent("example.com", "domain")
        ctx = make_context("example.com", "domain")

        events = module._events_from_variants(
            ["example.com", "example.net", "exampl3.com"],
            parent,
            ctx,
        )

        self.assertEqual({"similardomain"}, {event.event_type for event in events})
        self.assertEqual({"example.net", "exampl3.com"}, {event.value for event in events})

    def test_dnstwist_honors_spiderfoot_option_name_without_falling_back(self) -> None:
        module = DnsTwistModule()
        ctx = make_context(
            "example.com",
            "domain",
            {"dnstwist": {"dnstwistpath": "C:/missing/dnstwist.py"}},
        )

        variants = module._tool_variants(ctx, "example.com")

        self.assertEqual([], variants)

    def test_open_pdns_emits_raw_data_ip_and_affiliate_host(self) -> None:
        module = OpenPdnsModule()
        parent = make_parent("example.com", "domain")
        ctx = make_context("example.com", "domain")

        events = module._events_from_records(
            [
                {"rrname": "example.com", "rdata": "1.2.3.4", "rrtype": "A"},
                {"rrname": "cdn.other.net", "rdata": "9.9.9.9", "rrtype": "A"},
            ],
            parent,
            ctx,
        )

        event_types = {event.event_type for event in events}
        self.assertIn("raw_rir_data", event_types)
        self.assertIn("ip", event_types)
        self.assertIn("affiliate_internet_name", event_types)

    def test_open_pdns_honors_verify_hostnames_for_ip_queries(self) -> None:
        module = OpenPdnsModule()
        parent = make_parent("1.2.3.4", "ip")
        ctx = make_context("example.com", "domain")

        with patch(
            "python.cti_engine.modules.wave4_discovery._resolve_host_addresses",
            side_effect=[["1.2.3.4"], ["8.8.8.8"]],
        ):
            events = module._events_from_records(
                [
                    {"rrname": "match.example.com", "rdata": "1.2.3.4", "rrtype": "A"},
                    {"rrname": "stale.other.net", "rdata": "1.2.3.4", "rrtype": "A"},
                ],
                parent,
                ctx,
            )

        event_pairs = {(event.event_type, event.value) for event in events}
        self.assertIn(("internet_name", "match.example.com"), event_pairs)
        self.assertNotIn(("co_hosted_site", "stale.other.net"), event_pairs)

    def test_opennic_affiliate_source_emits_affiliate_ip_types(self) -> None:
        module = OpenNicModule()
        parent = make_parent("mirror.geek", "affiliate_internet_name")
        ctx = make_context("example.com", "domain")

        events = module._events_from_addresses(
            ["1.2.3.4", "2001:db8::1"],
            parent,
            ctx,
        )

        self.assertEqual(
            {"affiliate_ipaddr", "affiliate_ipv6"},
            {event.event_type for event in events},
        )

    def test_opennic_queries_only_a_records_like_spiderfoot(self) -> None:
        module = OpenNicModule()

        with patch("python.cti_engine.modules.wave4_discovery._dns_query_udp", return_value=None) as query_udp:
            result = module._query_opennic("mirror.geek", 5)

        self.assertEqual([], result)
        self.assertEqual(len(OPENNIC_NAMESERVERS), query_udp.call_count)
        self.assertTrue(all(call.args[2] == 1 for call in query_udp.call_args_list))

    def test_web_spider_emits_http_and_link_events_from_page(self) -> None:
        module = WebSpiderModule()
        parent = make_parent("https://example.com", "url")
        ctx = make_context("https://example.com", "url")

        events = module._events_from_page(
            "https://example.com",
            200,
            {"content-type": "text/html; charset=utf-8", "server": "Example"},
            """
            <html>
              <body>
                <a href="/login">Login</a>
                <a href="https://outside.net/page">Outside</a>
                <img src="https://cdn.example.com/logo.png" />
              </body>
            </html>
            """,
            parent,
            ctx,
        )

        event_types = {event.event_type for event in events}
        self.assertIn("http_code", event_types)
        self.assertIn("webserver_httpheaders", event_types)
        self.assertIn("target_web_content_type", event_types)
        self.assertIn("target_web_content", event_types)
        self.assertIn("linked_url_internal", event_types)
        self.assertIn("linked_url_external", event_types)

    def test_web_spider_uses_root_target_for_internal_link_classification(self) -> None:
        module = WebSpiderModule()
        parent = make_parent("shop.example.com", "internet_name")
        ctx = make_context("example.com", "domain")

        events = module._events_from_page(
            "https://shop.example.com/account",
            200,
            {"content-type": "text/html"},
            """
            <html>
              <body>
                <a href="https://cdn.example.com/lib.js">CDN</a>
                <a href="https://outside.net/page">Outside</a>
              </body>
            </html>
            """,
            parent,
            ctx,
        )

        internal_links = {event.value for event in events if event.event_type == "linked_url_internal"}
        external_links = {event.value for event in events if event.event_type == "linked_url_external"}
        self.assertIn("https://cdn.example.com/lib.js", internal_links)
        self.assertIn("https://outside.net/page", external_links)

    def test_web_spider_filtermime_skips_content_but_keeps_link_events(self) -> None:
        module = WebSpiderModule()
        parent = make_parent("https://example.com", "url")
        ctx = make_context(
            "example.com",
            "domain",
            {"web-spider": {"filtermime": "application/json"}},
        )

        events = module._events_from_page(
            "https://example.com/api",
            200,
            {"content-type": "application/json"},
            '<a href="/next">Next</a>',
            parent,
            ctx,
        )

        event_types = {event.event_type for event in events}
        self.assertIn("target_web_content_type", event_types)
        self.assertIn("linked_url_internal", event_types)
        self.assertNotIn("target_web_content", event_types)

    def test_web_spider_links_child_fetches_to_the_discovered_url_event(self) -> None:
        module = WebSpiderModule()
        parent = make_parent("example.com", "domain")
        ctx = make_context(
            "example.com",
            "domain",
            {"web-spider": {"start": ["http://"], "maxpages": 2, "maxlevels": 2}},
        )

        def fake_fetch(url, *_args, **_kwargs):
            if url == "http://example.com":
                return (
                    200,
                    '<a href="/about">About</a>',
                    "http://example.com",
                    {"content-type": "text/html"},
                )
            if url == "http://example.com/about":
                return (
                    200,
                    "<html>About</html>",
                    "http://example.com/about",
                    {"content-type": "text/html"},
                )
            return (0, "", url, {})

        with patch("python.cti_engine.modules.wave4_discovery._fetch_http", side_effect=fake_fetch):
            events = asyncio.run(collect(module, parent, ctx))

        about_link_event = next(
            event for event in events
            if event.event_type == "linked_url_internal" and event.value == "http://example.com/about"
        )
        about_http_code = next(
            event for event in events
            if event.event_type == "http_code" and event.parent_event_id == about_link_event.event_id
        )
        self.assertEqual("200", about_http_code.value)


if __name__ == "__main__":
    unittest.main()
