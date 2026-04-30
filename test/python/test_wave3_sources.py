from __future__ import annotations

import unittest

from python.cti_engine.context import ScanContext, ScanRequest
from python.cti_engine.events import ScanEvent
from python.cti_engine.modules.wave3_sources import (
    CrxCavatorModule,
    FlickrModule,
    GitHubModule,
    OnionSearchEngineModule,
    PgpKeyServersModule,
    TorchModule,
    WikipediaEditsModule,
    WikileaksModule,
)
from python.cti_engine.settings import SettingsSnapshot
from python.cti_engine.targets import normalize_target


def make_context(
    value: str,
    target_type: str,
    module_settings: dict[str, dict[str, object]] | None = None,
) -> ScanContext:
    return ScanContext(request=ScanRequest(
        scan_id=779,
        user_id=1,
        scan_name="Wave 3 Test",
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


class WaveThreeSourceModuleTests(unittest.TestCase):
    def test_flickr_extracts_emails_links_and_hosts(self) -> None:
        module = FlickrModule()
        parent = make_parent("example.com", "domain")
        ctx = make_context("example.com", "domain")

        events = module._events_from_photo_rows(
            [
                {
                    "description": "admin@example.com https://img.example.com/gallery",
                    "owner_name": "Example",
                }
            ],
            parent,
            ctx,
            dns_resolve=False,
        )

        event_types = {event.event_type for event in events}
        self.assertIn("email_generic", event_types)
        self.assertIn("linked_url_internal", event_types)
        self.assertIn("internet_name", event_types)
        self.assertIn("domain_name", event_types)

    def test_github_profile_emits_name_and_location(self) -> None:
        module = GitHubModule()
        parent = make_parent("Github: <SFURL>https://github.com/acme</SFURL>", "social_media")
        ctx = make_context("acme", "username")

        events = module._events_from_user_profile(
            {"login": "acme", "name": "Acme Inc", "location": "Quezon City"},
            parent,
            ctx,
        )

        self.assertEqual({"raw_rir_data", "geoinfo"}, {event.event_type for event in events})

    def test_github_repo_items_respect_names_only_and_strict_user(self) -> None:
        module = GitHubModule()
        parent = make_parent("acme", "username")
        ctx = make_context("acme", "username")

        events = module._events_from_repo_items(
            [
                {
                    "name": "acme",
                    "html_url": "https://github.com/acme/acme",
                    "description": "Main repo",
                },
                {
                    "name": "other",
                    "html_url": "https://github.com/acme/other",
                    "description": "Other repo",
                },
            ],
            "acme",
            parent,
            ctx,
            names_only=True,
            strict_user=True,
        )

        self.assertEqual(1, len(events))
        self.assertEqual("public_code_repo", events[0].event_type)

    def test_onionsearchengine_emits_darknet_url_when_fetch_disabled(self) -> None:
        module = OnionSearchEngineModule()
        parent = make_parent("example.com", "domain")
        ctx = make_context("example.com", "domain")

        events = module._events_from_search_page(
            '<a href="url.php?u=http%3A%2F%2Fabcdefghijklmnop.onion%2Fdocs">x</a>'
            '<a href="url.php?u=http%3A%2F%2Frelate.example.onion%2Fdocs">y</a>',
            parent,
            ctx,
            timeout=5,
            fetch_darknet=False,
            blacklist_patterns=[r".*://relate.*"],
        )

        self.assertEqual(["darknet_mention_url"], [event.event_type for event in events])

    def test_torch_emits_darknet_url_when_fetch_disabled(self) -> None:
        module = TorchModule()
        parent = make_parent("example.com", "domain")
        ctx = make_context("example.com", "domain")

        events = module._events_from_search_page(
            '<h5><a href="http://abcdefghijklmnop.onion/page" target="_blank">result</a>',
            parent,
            ctx,
            timeout=5,
            fetch_darknet=False,
        )

        self.assertEqual(["darknet_mention_url"], [event.event_type for event in events])

    def test_wikileaks_extracts_nested_leak_links_only(self) -> None:
        module = WikileaksModule()
        parent = make_parent("example.com", "domain")
        ctx = make_context("example.com", "domain")

        events = module._events_from_search_page(
            "https://search.wikileaks.org/?query=example.com",
            '<a href="https://wikileaks.org/leak/folder/file.pdf">a</a>'
            '<a href="https://search.wikileaks.org/page=2">b</a>'
            '<a href="https://cryptome.org/2020/01/file.htm">c</a>'
            '<a href="https://wikileaks.org/app.css">d</a>',
            parent,
            ctx,
        )

        self.assertEqual({"leaksite_url"}, {event.event_type for event in events})
        self.assertEqual(2, len(events))

    def test_wikipedia_edits_extracts_edit_links(self) -> None:
        module = WikipediaEditsModule()
        parent = make_parent("ExampleUser", "username")
        ctx = make_context("ExampleUser", "username")

        events = module._events_from_payload(
            "<feed>"
            "<link>https://en.wikipedia.org/wiki/Test</link>"
            "<link>https://en.wikipedia.org/wiki/Special:Contributions/ExampleUser</link>"
            "</feed>",
            parent,
            ctx,
        )

        self.assertEqual(["wikipedia_page_edit"], [event.event_type for event in events])

    def test_wikipedia_edits_normalizes_username_input(self) -> None:
        module = WikipediaEditsModule()

        self.assertEqual("ExampleUser", module._normalize_actor('"ExampleUser"', "username"))
        self.assertEqual("ExampleUser", module._normalize_actor("@ExampleUser", "username"))
        self.assertEqual("ExampleUser", module._normalize_actor("'ExampleUser'", "username"))

    def test_pgp_domain_content_classifies_target_generic_and_affiliate_emails(self) -> None:
        module = PgpKeyServersModule()
        parent = make_parent("example.com", "domain")
        ctx = make_context("example.com", "domain")

        events = module._events_from_domain_content(
            "alice@example.com admin@example.com bob@other.net",
            parent,
            ctx,
        )

        event_types = {event.event_type for event in events}
        self.assertIn("email", event_types)
        self.assertIn("email_generic", event_types)
        self.assertIn("affiliate_email", event_types)

    def test_pgp_key_content_extracts_public_key_blocks(self) -> None:
        module = PgpKeyServersModule()
        parent = make_parent("alice@example.com", "email")
        ctx = make_context("alice@example.com", "email")
        sample_key = (
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
            + ("A" * 320)
            + "\n-----END PGP PUBLIC KEY BLOCK-----"
        )

        events = module._events_from_key_content(sample_key, parent, ctx)

        self.assertEqual(["pgp_key"], [event.event_type for event in events])

    def test_crxcavator_emits_appstore_hosts_urls_and_address(self) -> None:
        module = CrxCavatorModule()
        parent = make_parent("example.com", "domain")
        ctx = make_context("example.com", "domain")

        events = module._events_from_extension_payload(
            "abc123",
            [
                {
                    "data": {
                        "manifest": {"version": "1.0"},
                        "webstore": {
                            "name": "Example Extension",
                            "privacy_policy": "https://example.com/privacy",
                            "support_site": "https://support.example.com/help",
                            "offered_by": "https://vendor.example.net",
                            "website": "https://example.com",
                            "address": "123 Example Street, Makati City",
                        },
                    }
                }
            ],
            parent,
            ctx,
            verify_hosts=False,
        )

        event_types = {event.event_type for event in events}
        self.assertIn("appstore_entry", event_types)
        self.assertIn("linked_url_internal", event_types)
        self.assertIn("internet_name", event_types)
        self.assertIn("affiliate_internet_name", event_types)
        self.assertIn("physical_address", event_types)


if __name__ == "__main__":
    unittest.main()
