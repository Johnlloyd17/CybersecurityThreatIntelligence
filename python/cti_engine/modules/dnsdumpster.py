"""DNSDumpster module aligned to SpiderFoot's passive subdomain flow."""

from __future__ import annotations

from http.cookies import SimpleCookie
import re
import socket
import urllib.parse
import urllib.request
from typing import AsyncIterator

from ..events import ScanEvent
from ..module_base import BaseModule


class DnsDumpsterModule(BaseModule):
    slug = "dnsdumpster"
    name = "DNSDumpster"
    watched_types = {"domain", "internet_name"}
    produced_types = {"internet_name", "internet_name_unresolved"}
    requires_key = False

    HOME_URL = "https://dnsdumpster.com"
    FORM_URL = "https://dnsdumpster.com/"

    def __init__(self) -> None:
        self._seen: set[str] = set()

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        query = str(event.value or "").strip().lower()
        if not query:
            return

        if query in self._seen:
            ctx.debug(f"Skipping {query}, already checked.", self.slug)
            return
        self._seen.add(query)

        timeout = int(ctx.request.settings.global_settings.get("http_timeout", 15) or 15)
        for hostname in self._query(query, timeout, ctx):
            if not self._is_child_of_target(hostname, ctx.root_target):
                continue

            event_type = "internet_name" if self._resolves(hostname) else "internet_name_unresolved"
            yield ScanEvent(
                event_type=event_type,
                value=hostname,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=event.event_id,
                confidence=78,
                visibility=100,
                risk_score=5,
                tags=["dnsdumpster", "subdomain"],
                raw_payload={"query": query},
            )

    def _query(self, domain: str, timeout: int, ctx) -> list[str]:
        initial_request = urllib.request.Request(
            self.HOME_URL,
            headers={"User-Agent": "CTI Engine"},
            method="GET",
        )

        try:
            with urllib.request.urlopen(initial_request, timeout=timeout) as response:  # nosec - fixed provider URL
                initial_status = int(getattr(response, "status", 200) or 200)
                initial_html = response.read().decode("utf-8", errors="replace")
                cookie_header = str(response.headers.get("Set-Cookie", "") or "")
        except Exception as exc:
            ctx.warning(f"DNSDumpster bootstrap request failed: {exc}", self.slug)
            return []

        if initial_status != 200:
            ctx.warning(f"DNSDumpster returned HTTP {initial_status} during bootstrap.", self.slug)
            return []

        csrftoken = self._extract_cookie(cookie_header, "csrftoken")
        csrfmiddlewaretoken = self._extract_hidden_token(initial_html)
        if not csrftoken or not csrfmiddlewaretoken:
            ctx.warning("DNSDumpster did not return the expected CSRF tokens.", self.slug)
            return []

        body = urllib.parse.urlencode({
            "csrfmiddlewaretoken": csrfmiddlewaretoken,
            "targetip": domain,
            "user": "free",
        }).encode("utf-8")
        followup_request = urllib.request.Request(
            self.FORM_URL,
            headers={
                "User-Agent": "CTI Engine",
                "Origin": self.HOME_URL,
                "Referer": self.FORM_URL,
                "Content-Type": "application/x-www-form-urlencoded",
                "Cookie": f"csrftoken={csrftoken}",
            },
            data=body,
            method="POST",
        )

        try:
            with urllib.request.urlopen(followup_request, timeout=timeout) as response:  # nosec - fixed provider URL
                status = int(getattr(response, "status", 200) or 200)
                content = response.read().decode("utf-8", errors="replace")
        except Exception as exc:
            ctx.warning(f"DNSDumpster search request failed: {exc}", self.slug)
            return []

        if status != 200:
            ctx.warning(f"DNSDumpster returned HTTP {status} for {domain}.", self.slug)
            return []

        return self._extract_subdomains(content, domain)

    def _extract_cookie(self, header_value: str, key: str) -> str | None:
        cookie = SimpleCookie()
        try:
            cookie.load(header_value)
        except Exception:
            return None
        morsel = cookie.get(key)
        if morsel is None:
            return None
        value = str(morsel.value or "").strip()
        return value or None

    def _extract_hidden_token(self, html: str) -> str | None:
        match = re.search(
            r'name=["\']csrfmiddlewaretoken["\'][^>]*value=["\']([^"\']+)["\']',
            html,
            flags=re.I,
        )
        if not match:
            return None
        value = str(match.group(1) or "").strip()
        return value or None

    def _extract_subdomains(self, html: str, domain: str) -> list[str]:
        escaped_domain = re.escape(str(domain or "").strip().lower())
        pattern = re.compile(rf"\b(?:[a-z0-9_-]+\.)+{escaped_domain}\b", re.I)

        discovered: set[str] = set()
        for match in pattern.finditer(html or ""):
            hostname = str(match.group(0) or "").strip().lower().rstrip(".")
            if not hostname or hostname == domain.lower():
                continue
            discovered.add(hostname)

        return sorted(discovered)

    def _is_child_of_target(self, hostname: str, root_target: str) -> bool:
        candidate = str(hostname or "").strip().lower().rstrip(".")
        root = str(root_target or "").strip().lower().rstrip(".")
        if not candidate or not root or candidate == root:
            return False
        return candidate.endswith("." + root)

    def _resolves(self, hostname: str) -> bool:
        try:
            return bool(socket.getaddrinfo(hostname, None))
        except OSError:
            return False
