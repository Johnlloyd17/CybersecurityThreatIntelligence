from __future__ import annotations

import asyncio
import socket
import unittest
from unittest.mock import patch

from python.cti_engine.context import ScanContext, ScanRequest
from python.cti_engine.events import ScanEvent
from python.cti_engine.modules.dnsresolve import DnsResolveModule
from python.cti_engine.settings import SettingsSnapshot
from python.cti_engine.targets import normalize_target


class DnsResolveModuleTests(unittest.TestCase):
    def test_dnsresolve_emits_ip_events(self) -> None:
        module = DnsResolveModule()
        request = ScanRequest(
            scan_id=3,
            user_id=1,
            scan_name="DNS Test",
            target=normalize_target("example.com", "domain"),
            selected_modules=["dnsresolve"],
            settings=SettingsSnapshot(),
        )
        ctx = ScanContext(request=request)
        event = ScanEvent(
            event_type="domain",
            value="example.com",
            source_module="seed",
            root_target="example.com",
        )

        fake_answers = [
            (socket.AF_INET, None, None, None, ("93.184.216.34", 0)),
            (socket.AF_INET6, None, None, None, ("2606:2800:220:1:248:1893:25c8:1946", 0, 0, 0)),
        ]

        with patch("socket.getaddrinfo", return_value=fake_answers):
            results = asyncio.run(_collect(module.handle(event, ctx)))

        self.assertEqual({item.event_type for item in results}, {"ip", "ipv6"})


async def _collect(iterator):
    output = []
    async for item in iterator:
        output.append(item)
    return output


if __name__ == "__main__":
    unittest.main()

