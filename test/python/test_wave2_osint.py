from __future__ import annotations

import unittest
from unittest.mock import patch

from python.cti_engine.context import ScanContext, ScanRequest
from python.cti_engine.events import ScanEvent
from python.cti_engine.modules.wave2_osint import (
    AhmiaModule,
    DnsBruteforceModule,
    DnsGrepModule,
    DnsRawModule,
    DuckDuckGoModule,
    GrepAppModule,
    SearchcodeModule,
    SslAnalyzerModule,
    TldSearcherModule,
    VoipBlModule,
)
from python.cti_engine.settings import SettingsSnapshot
from python.cti_engine.targets import normalize_target


def make_context(
    value: str,
    target_type: str,
    module_settings: dict[str, dict[str, object]] | None = None,
) -> ScanContext:
    return ScanContext(request=ScanRequest(
        scan_id=778,
        user_id=1,
        scan_name="Wave 2 Test",
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


class WaveTwoOsintModuleTests(unittest.TestCase):
    def test_ahmia_emits_darknet_url_only_when_page_fetch_disabled(self) -> None:
        module = AhmiaModule()
        parent = make_parent("example.com", "domain")
        ctx = make_context("example.com", "domain")

        events = module._events_from_search_page(
            '<a href="/redirect?redirect_url=http%3A%2F%2Fabcdefghijklmnop.onion%2Findex">result</a>',
            parent,
            ctx,
            timeout=5,
            fetch_darknet_pages=False,
        )

        self.assertEqual(["darknet_mention_url"], [event.event_type for event in events])

    def test_ahmia_fetch_verifies_target_mention_before_emitting_content(self) -> None:
        module = AhmiaModule()
        parent = make_parent("example.com", "domain")
        ctx = make_context("example.com", "domain")

        with patch("python.cti_engine.modules.wave2_osint._fetch_text") as fetch_text:
            fetch_text.return_value = "before example.com after"
            events = module._events_from_search_page(
                '<a href="/redirect?redirect_url=http%3A%2F%2Fabcdefghijklmnop.onion%2Findex">result</a>',
                parent,
                ctx,
                timeout=5,
                fetch_darknet_pages=True,
            )

        self.assertEqual(
            {"darknet_mention_url", "darknet_mention_content"},
            {event.event_type for event in events},
        )

    def test_dns_bruteforce_emits_internet_names_for_resolved_hosts(self) -> None:
        module = DnsBruteforceModule()
        parent = make_parent("example.com", "domain")
        ctx = make_context("example.com", "domain")

        events = module._events_from_resolutions(
            {
                "www.example.com": True,
                "dev.example.com": False,
                "api.example.com": True,
            },
            parent,
            ctx,
        )

        self.assertEqual(["api.example.com", "www.example.com"], [event.value for event in events])
        self.assertEqual({"internet_name"}, {event.event_type for event in events})

    def test_dns_raw_emits_providers_text_spf_and_related_hosts(self) -> None:
        module = DnsRawModule()
        parent = make_parent("example.com", "domain")
        ctx = make_context("example.com", "domain", {"dns-raw": {"verify": False}})

        events = module._events_from_records(
            [
                {"type": "MX", "value": "mail.example.com", "raw": "MX mail.example.com"},
                {"type": "NS", "value": "ns1.example.com", "raw": "NS ns1.example.com"},
                {"type": "TXT", "value": "v=spf1 include:spf.example.com ~all", "raw": 'TXT "v=spf1 include:spf.example.com ~all"'},
                {"type": "CNAME", "value": "cdn.example.com", "raw": "CNAME cdn.example.com"},
            ],
            parent,
            ctx,
        )

        event_types = {event.event_type for event in events}
        self.assertIn("provider_mail", event_types)
        self.assertIn("provider_dns", event_types)
        self.assertIn("raw_dns_records", event_types)
        self.assertIn("dns_text", event_types)
        self.assertIn("dns_spf", event_types)
        self.assertIn("internet_name", event_types)

    def test_dnsgrep_emits_raw_data_and_hostname(self) -> None:
        module = DnsGrepModule()
        parent = make_parent("example.com", "domain")
        ctx = make_context("example.com", "domain", {"dnsgrep": {"dns_resolve": False}})
        payload = {
            "FDNS_A": ["1.2.3.4,www.example.com"],
            "RDNS": ["5.6.7.8,mail.example.com"],
        }

        events = module._events_from_payload(
            payload,
            parent,
            ctx,
        )

        event_types = {event.event_type for event in events}
        self.assertIn("raw_rir_data", event_types)
        self.assertIn("internet_name", event_types)
        self.assertEqual(str(payload), events[0].value)

    def test_duckduckgo_requires_heading_and_ignores_nested_topics(self) -> None:
        module = DuckDuckGoModule()
        parent = make_parent("example.com", "domain")
        ctx = make_context("example.com", "domain")

        self.assertEqual([], module._events_from_payload({"AbstractText": "Example abstract"}, parent, ctx))

        events = module._events_from_payload(
            {
                "Heading": "Example",
                "AbstractText": "Example abstract",
                "RelatedTopics": [
                    {"Text": "Example category"},
                    {"Topics": [{"Text": "Nested topic"}]},
                ],
            },
            parent,
            ctx,
        )

        event_types = {event.event_type for event in events}
        self.assertIn("description_abstract", event_types)
        self.assertIn("description_category", event_types)
        self.assertEqual(2, len(events))

    def test_grepapp_extracts_internal_links_emails_and_hosts(self) -> None:
        module = GrepAppModule()
        parent = make_parent("example.com", "domain")
        ctx = make_context("example.com", "domain", {"grep-app": {"dns_resolve": False}})

        events = module._events_from_payload(
            {
                "facets": {"count": 1},
                "hits": {
                    "hits": [
                        {
                            "_source": {
                                "content": {
                                    "snippet": "<mark>https://www.example.com/login</mark> admin@example.com"
                                }
                            }
                        }
                    ]
                },
            },
            parent,
            ctx,
        )

        event_types = {event.event_type for event in events}
        self.assertIn("raw_rir_data", event_types)
        self.assertIn("linked_url_internal", event_types)
        self.assertIn("email_generic", event_types)
        self.assertIn("internet_name", event_types)
        self.assertIn("domain_name", event_types)

    def test_searchcode_extracts_repo_links_emails_and_hosts(self) -> None:
        module = SearchcodeModule()
        parent = make_parent("example.com", "domain")
        ctx = make_context("example.com", "domain", {"searchcode": {"dns_resolve": False}})

        events = module._events_from_payload(
            {
                "results": [
                    {
                        "repo": "org/repo",
                        "url": "https://searchcode.com/file/1/",
                        "lines": {
                            "1": "See https://app.example.com/ and admin@example.com"
                        },
                    }
                ]
            },
            parent,
            ctx,
        )

        event_types = {event.event_type for event in events}
        self.assertIn("public_code_repo", event_types)
        self.assertIn("raw_rir_data", event_types)
        self.assertIn("linked_url_internal", event_types)
        self.assertIn("email_generic", event_types)
        self.assertIn("internet_name", event_types)

    def test_ssl_analyzer_prefers_textual_certificate_view(self) -> None:
        module = SslAnalyzerModule()
        parent = make_parent("www.example.com", "internet_name")
        ctx = make_context("www.example.com", "domain")

        events = module._events_from_certificate(
            {
                "subject": ((("commonName", "www.example.com"),),),
                "issuer": ((("organizationName", "Example CA"),),),
                "subjectAltName": (("DNS", "www.example.com"), ("DNS", "api.example.com")),
                "notAfter": "Dec 31 23:59:59 2099 GMT",
                "text": "Certificate:\n    Subject: CN=www.example.com",
            },
            "-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----",
            "www.example.com",
            443,
            parent_event=parent,
            ctx=ctx,
            verify_hosts=False,
        )

        event_types = {event.event_type for event in events}
        self.assertIn("tcp_port_open", event_types)
        self.assertIn("ssl_certificate_raw", event_types)
        self.assertIn("ssl_certificate_issuer", event_types)
        self.assertIn("ssl_certificate_issued", event_types)
        self.assertIn("internet_name", event_types)
        self.assertIn("domain_name", event_types)
        raw_event = next(event for event in events if event.event_type == "ssl_certificate_raw")
        self.assertEqual("Certificate:\n    Subject: CN=www.example.com", raw_event.value)

    def test_tld_searcher_emits_only_other_resolved_tlds(self) -> None:
        module = TldSearcherModule()
        parent = make_parent("example.com", "domain")
        ctx = make_context("example.com", "domain")

        events = module._events_from_variants(
            {
                "example.com": True,
                "example.net": True,
                "example.org": False,
            },
            parent,
            ctx,
        )

        self.assertEqual(["example.net"], [event.value for event in events])
        self.assertEqual({"similardomain"}, {event.event_type for event in events})

    def test_tld_searcher_can_skip_wildcard_tlds(self) -> None:
        module = TldSearcherModule()
        parent = make_parent("example.com", "domain")
        ctx = make_context("example.com", "domain")

        with patch.object(module, "_has_wildcard_tld", side_effect=lambda tld: tld == "net"):
            events = module._events_from_variants(
                {
                    "example.net": True,
                    "example.org": True,
                },
                parent,
                ctx,
                skip_wildcards=True,
            )

        self.assertEqual(["example.org"], [event.value for event in events])

    def test_voipbl_emits_malicious_and_blacklisted_ip(self) -> None:
        module = VoipBlModule()
        parent = make_parent("1.2.3.4", "ip")
        ctx = make_context("1.2.3.4", "ip")

        events = module._events_from_feed(
            "# comment\n1.2.3.0/24\n",
            parent_event=parent,
            ctx=ctx,
        )

        self.assertEqual({"malicious_ip", "blacklisted_ip"}, {event.event_type for event in events})


if __name__ == "__main__":
    unittest.main()
