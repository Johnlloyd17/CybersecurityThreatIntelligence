from __future__ import annotations

import unittest

from python.cti_engine.modules import register_builtin_modules
from python.cti_engine.registry import ModuleRegistry


class RegistryTests(unittest.TestCase):
    def test_builtin_modules_register(self) -> None:
        registry = ModuleRegistry()
        register_builtin_modules(registry)
        self.assertTrue(registry.has("apivoid"))
        self.assertTrue(registry.has("abuse-ch"))
        self.assertTrue(registry.has("abuseipdb"))
        self.assertTrue(registry.has("alienvault"))
        self.assertTrue(registry.has("certspotter"))
        self.assertTrue(registry.has("crt-sh"))
        self.assertTrue(registry.has("dnsresolve"))
        self.assertTrue(registry.has("jsonwhois"))
        self.assertTrue(registry.has("shodan"))
        self.assertTrue(registry.has("urlscan"))
        self.assertTrue(registry.has("virustotal"))
        self.assertTrue(registry.has("whoisology"))
        self.assertTrue(registry.has("whoxy"))


if __name__ == "__main__":
    unittest.main()
