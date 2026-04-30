from __future__ import annotations

import asyncio
import io
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch
import zipfile
from pathlib import Path

from python.cti_engine.context import ScanContext, ScanRequest
from python.cti_engine.events import ScanEvent
from python.cti_engine.modules.wave5_extractors import (
    AccountFinderModule,
    BinaryStringExtractorModule,
    CmSeekModule,
    CompanyNameExtractorModule,
    CountryNameExtractorModule,
    CrossReferencerModule,
    FileMetadataExtractorModule,
    HumanNameExtractorModule,
    InterestingFileFinderModule,
    JunkFileFinderModule,
)
from python.cti_engine.settings import SettingsSnapshot
from python.cti_engine.targets import normalize_target


def make_context(
    value: str,
    target_type: str,
    module_settings: dict[str, dict[str, object]] | None = None,
) -> ScanContext:
    return ScanContext(request=ScanRequest(
        scan_id=990,
        user_id=1,
        scan_name="Wave 5 Test",
        target=normalize_target(value, target_type),
        selected_modules=[],
        settings=SettingsSnapshot(module_settings=module_settings or {}),
    ))


def make_parent(
    value: str,
    event_type: str,
    *,
    source_module: str = "seed",
    raw_payload: dict[str, object] | None = None,
    root_target: str | None = None,
) -> ScanEvent:
    return ScanEvent(
        event_type=event_type,
        value=value,
        source_module=source_module,
        root_target=root_target or value,
        raw_payload=dict(raw_payload or {}),
    )


async def collect(module, parent: ScanEvent, ctx: ScanContext) -> list[ScanEvent]:
    return [child async for child in module.handle(parent, ctx)]


def office_payload(author: str = "Jane Doe", comments: str = "Prepared in CTI") -> bytes:
    content = io.BytesIO()
    core_xml = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
 xmlns:dc="http://purl.org/dc/elements/1.1/">
  <dc:creator>{author}</dc:creator>
  <dc:description>{comments}</dc:description>
</cp:coreProperties>
"""
    with zipfile.ZipFile(content, "w") as archive:
        archive.writestr("docProps/core.xml", core_xml)
    return content.getvalue()


class WaveFiveExtractorModuleTests(unittest.TestCase):
    def test_account_finder_emits_username_from_domain_seed(self) -> None:
        module = AccountFinderModule()
        parent = make_parent("example.com", "domain")
        ctx = make_context("example.com", "domain")

        events = asyncio.run(collect(module, parent, ctx))

        self.assertEqual(["username"], [event.event_type for event in events])
        self.assertEqual(["example"], [event.value for event in events])

    def test_binary_string_extractor_honors_cti_setting_aliases(self) -> None:
        module = BinaryStringExtractorModule()
        parent = make_parent("https://example.com/archive.bin", "url", root_target="example.com")
        ctx = make_context(
            "https://example.com/archive.bin",
            "url",
            {
                "binary-string-extractor": {
                    "file_types": "bin",
                    "use_dictionary": False,
                    "min_string_length": 5,
                    "max_strings": 2,
                }
            },
        )

        with patch(
            "python.cti_engine.modules.wave5_extractors._fetch_binary",
            return_value=b"hello\x00world\x00ignored-string",
        ):
            events = asyncio.run(collect(module, parent, ctx))

        self.assertEqual(1, len(events))
        self.assertEqual("raw_file_meta_data", events[0].event_type)
        self.assertEqual("hello\nworld", events[0].value)

    def test_company_name_extractor_finds_company_name_from_content(self) -> None:
        module = CompanyNameExtractorModule()
        parent = make_parent(
            "Copyright Example LLC. Another Vendor GmbH.",
            "target_web_content",
            raw_payload={"source_url": "https://example.com/about"},
            root_target="example.com",
        )
        ctx = make_context("example.com", "domain")

        events = asyncio.run(collect(module, parent, ctx))

        self.assertIn(("company_name", "Example LLC"), {(event.event_type, event.value) for event in events})

    def test_country_name_extractor_supports_similardomain_flag(self) -> None:
        module = CountryNameExtractorModule()
        parent = make_parent("example.ph", "similardomain", root_target="example.com")
        ctx = make_context(
            "example.com",
            "domain",
            {"country-name-extractor": {"check_similar_domains": True}},
        )

        events = asyncio.run(collect(module, parent, ctx))

        self.assertEqual([("country_name", "Philippines")], [(event.event_type, event.value) for event in events])

    def test_cross_referencer_emits_affiliate_events_for_linkback(self) -> None:
        module = CrossReferencerModule()
        parent = make_parent("example.com", "domain")
        ctx = make_context("example.com", "domain")

        with patch(
            "python.cti_engine.modules.wave5_extractors._first_page_content",
            return_value=('<a href="https://affiliate.test/about">About</a>', "https://example.com", {}),
        ), patch(
            "python.cti_engine.modules.wave5_extractors._host_resolves",
            return_value=True,
        ), patch(
            "python.cti_engine.modules.wave5_extractors._fetch_http",
            return_value=(200, "Our partner example.com is listed here.", "https://affiliate.test/about", {}),
        ):
            events = asyncio.run(collect(module, parent, ctx))

        pairs = [(event.event_type, event.value) for event in events]
        self.assertIn(("affiliate_internet_name", "affiliate.test"), pairs)
        self.assertIn(("affiliate_web_content", "Our partner example.com is listed here."), pairs)

    def test_file_metadata_extractor_reads_docx_core_properties(self) -> None:
        module = FileMetadataExtractorModule()
        parent = make_parent("https://example.com/report.docx", "url", root_target="example.com")
        ctx = make_context(
            "https://example.com/report.docx",
            "url",
            {"file-metadata-extractor": {"file_extensions": "docx", "download_timeout": 10}},
        )

        with patch(
            "python.cti_engine.modules.wave5_extractors._fetch_binary",
            return_value=office_payload(),
        ):
            events = asyncio.run(collect(module, parent, ctx))

        self.assertIn(("raw_file_meta_data", "Author: Jane Doe, Comments: Prepared in CTI"), [(event.event_type, event.value) for event in events])
        self.assertIn(("software_used", "Jane Doe"), [(event.event_type, event.value) for event in events])

    def test_human_name_extractor_builds_name_from_email_generic(self) -> None:
        module = HumanNameExtractorModule()
        parent = make_parent("jane.doe@example.com", "email_generic", root_target="example.com")
        ctx = make_context("example.com", "domain")

        events = asyncio.run(collect(module, parent, ctx))

        self.assertEqual([("human_name", "Jane Doe")], [(event.event_type, event.value) for event in events])

    def test_human_name_extractor_rejects_untrusted_raw_rir_source(self) -> None:
        module = HumanNameExtractorModule()
        parent = make_parent("Jane Doe joined Example LLC", "raw_rir_data", source_module="unknown", root_target="example.com")
        ctx = make_context("example.com", "domain")

        events = asyncio.run(collect(module, parent, ctx))

        self.assertEqual([], events)

    def test_interesting_file_finder_emits_internal_matching_links(self) -> None:
        module = InterestingFileFinderModule()
        parent = make_parent("example.com", "domain")
        ctx = make_context("example.com", "domain")

        with patch(
            "python.cti_engine.modules.wave5_extractors._first_page_content",
            return_value=(
                '<a href="/docs/report.pdf">PDF</a><a href="https://external.test/file.pdf">External</a>',
                "https://example.com",
                {},
            ),
        ):
            events = asyncio.run(collect(module, parent, ctx))

        self.assertEqual([("interesting_file", "https://example.com/docs/report.pdf")], [(event.event_type, event.value) for event in events])

    def test_junk_file_finder_emits_confirmed_candidate(self) -> None:
        module = JunkFileFinderModule()
        parent = make_parent("https://example.com/admin/login.php", "url", root_target="example.com")
        ctx = make_context("example.com", "domain")

        with patch.object(module, "_candidate_urls", return_value=["https://example.com/admin/login.php.bak"]), patch(
            "python.cti_engine.modules.wave5_extractors._head_status",
            return_value=(200, "https://example.com/admin/login.php.bak"),
        ), patch.object(module, "_valid_404", return_value=True):
            events = asyncio.run(collect(module, parent, ctx))

        self.assertEqual([("junk_file", "https://example.com/admin/login.php.bak")], [(event.event_type, event.value) for event in events])

    def test_cmseek_reads_result_file_from_configured_path(self) -> None:
        module = CmSeekModule()
        temp_dir = Path("runtime") / "test_wave5_cmseek"
        if temp_dir.exists():
            shutil.rmtree(temp_dir, ignore_errors=True)
        try:
            tool_path = temp_dir / "cmseek"
            tool_path.mkdir(parents=True, exist_ok=True)
            with open(tool_path / "cmseek.py", "w", encoding="utf-8") as handle:
                handle.write("#!/usr/bin/env python\n")
            result_dir = tool_path / "Result" / "example.com"
            result_dir.mkdir(parents=True, exist_ok=True)
            (result_dir / "cms.json").write_text('{"cms_name":"WordPress","cms_version":"6.0"}', encoding="utf-8")

            parent = make_parent("example.com", "domain")
            ctx = make_context(
                "example.com",
                "domain",
                {"cmseek": {"cmseek_path": str(tool_path), "python_path": sys.executable}},
            )

            with patch(
                "python.cti_engine.modules.wave5_extractors.subprocess.run",
                return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            ):
                events = asyncio.run(collect(module, parent, ctx))
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

        self.assertEqual([("software_used", "WordPress 6.0")], [(event.event_type, event.value) for event in events])


if __name__ == "__main__":
    unittest.main()
