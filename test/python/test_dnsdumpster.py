from __future__ import annotations

import unittest

from python.cti_engine.modules.dnsdumpster import DnsDumpsterModule


class DnsDumpsterModuleTests(unittest.TestCase):
    def test_extract_subdomains_returns_discovered_children(self) -> None:
        module = DnsDumpsterModule()
        html = """
        <html>
          <body>
            api.example.com
            www.example.com
            example.com
            not-example.org
          </body>
        </html>
        """

        results = module._extract_subdomains(html, "example.com")
        self.assertEqual(["api.example.com", "www.example.com"], results)

    def test_extract_hidden_token_reads_csrfmiddlewaretoken(self) -> None:
        module = DnsDumpsterModule()
        html = '<input type="hidden" name="csrfmiddlewaretoken" value="abc123token">'
        self.assertEqual("abc123token", module._extract_hidden_token(html))


if __name__ == "__main__":
    unittest.main()
