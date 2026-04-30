from __future__ import annotations

import asyncio
import subprocess
import unittest
from unittest.mock import patch

from python.cti_engine.context import ScanContext, ScanRequest
from python.cti_engine.events import ScanEvent
from python.cti_engine.modules.wave7_tools import (
    NbtscanModule,
    NmapModule,
    NucleiModule,
    OneSixtyOneModule,
    PortScannerTcpModule,
    TruffleHogModule,
    Wafw00fModule,
    WappalyzerModule,
    WhatWebModule,
)
from python.cti_engine.settings import SettingsSnapshot
from python.cti_engine.targets import normalize_target


def make_context(value: str, target_type: str) -> ScanContext:
    return ScanContext(request=ScanRequest(
        scan_id=1470,
        user_id=1,
        scan_name="Wave 7 Test",
        target=normalize_target(value, target_type),
        selected_modules=[],
        settings=SettingsSnapshot(),
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


class WaveSevenToolModuleTests(unittest.TestCase):
    def test_nbtscan_parses_netbios_name(self) -> None:
        module = NbtscanModule()
        parent = make_parent("192.0.2.10", "ip")
        ctx = make_context("192.0.2.10", "ip")

        events = module._events_from_output("192.0.2.10 SERVER <server>\n", parent, ctx)

        self.assertEqual([("netbios_name", "SERVER")], [(event.event_type, event.value) for event in events])

    def test_nmap_parses_xml_output(self) -> None:
        module = NmapModule()
        parent = make_parent("scanme.nmap.org", "domain")
        ctx = make_context("scanme.nmap.org", "domain")

        events = module._events_from_nmap_output(
            '<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>',
            parent,
            ctx,
        )

        self.assertEqual([("open_tcp_port", "scanme.nmap.org:80 (http)")], [(event.event_type, event.value) for event in events])

    def test_port_scanner_uses_socket_scan_fallback(self) -> None:
        module = PortScannerTcpModule()
        parent = make_parent("example.com", "domain")
        ctx = make_context("example.com", "domain")

        with patch("python.cti_engine.modules.wave7_tools._tool_path", return_value=None), patch(
            "python.cti_engine.modules.wave7_tools._scan_open_ports",
            return_value=[(443, "HTTPS")],
        ):
            events = asyncio.run(collect(module, parent, ctx))

        self.assertEqual([("open_tcp_port", "port-scanner-tcp")], [(event.event_type, event.source_module) for event in events])

    def test_nuclei_parses_jsonl_finding(self) -> None:
        module = NucleiModule()
        parent = make_parent("https://example.com", "url")
        ctx = make_context("https://example.com", "url")

        events = module._events_from_jsonl(
            '{"template-id":"exposed-env","matched-at":"https://example.com/.env","info":{"severity":"high"}}\n',
            parent,
            ctx,
        )

        self.assertEqual([("vulnerability", "nuclei")], [(event.event_type, event.source_module) for event in events])
        self.assertGreaterEqual(events[0].risk_score, 70)

    def test_onesixtyone_emits_snmp_info_from_tool_output(self) -> None:
        module = OneSixtyOneModule()
        parent = make_parent("192.0.2.10", "ip")
        ctx = make_context("192.0.2.10", "ip")

        with patch("python.cti_engine.modules.wave7_tools._tool_path", return_value="onesixtyone"), patch(
            "python.cti_engine.modules.wave7_tools._run_tool",
            return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout="192.0.2.10 public system\n", stderr=""),
        ):
            events = asyncio.run(collect(module, parent, ctx))

        self.assertEqual([("snmp_info", "onesixtyone")], [(event.event_type, event.source_module) for event in events])

    def test_trufflehog_detects_secret_patterns(self) -> None:
        module = TruffleHogModule()
        parent = make_parent("example.com", "domain")
        ctx = make_context("example.com", "domain")

        events = module._events_from_content("api_key = '1234567890abcdef123456'", "https://example.com/app.js", parent, ctx)

        self.assertEqual([("secret_leak", "trufflehog")], [(event.event_type, event.source_module) for event in events])

    def test_wafw00f_detects_cloudflare_header(self) -> None:
        module = Wafw00fModule()
        parent = make_parent("example.com", "domain")
        ctx = make_context("example.com", "domain")

        events = module._events_from_response(200, "", "https://example.com", {"cf-ray": "abc"}, parent, ctx)

        self.assertEqual([("web_application_firewall", "Cloudflare")], [(event.event_type, event.value.split(": ", 1)[1]) for event in events])

    def test_wappalyzer_detects_technology_from_headers_and_body(self) -> None:
        module = WappalyzerModule()
        parent = make_parent("example.com", "domain")
        ctx = make_context("example.com", "domain")

        events = module._events_from_response(
            "<html><script src='/wp-content/jquery.js'></script></html>",
            {"server": "nginx"},
            "https://example.com",
            parent,
            ctx,
        )

        self.assertIn(("software_used", "nginx (Web Server)"), [(event.event_type, event.value) for event in events])
        self.assertIn(("software_used", "WordPress (CMS)"), [(event.event_type, event.value) for event in events])

    def test_whatweb_includes_raw_web_header_summary(self) -> None:
        module = WhatWebModule()
        parent = make_parent("example.com", "domain")
        ctx = make_context("example.com", "domain")

        events = module._events_from_response(
            "<title>Example</title>",
            {"server": "Apache"},
            "https://example.com",
            parent,
            ctx,
        )

        self.assertIn("raw_web_header", {event.event_type for event in events})


if __name__ == "__main__":
    unittest.main()
