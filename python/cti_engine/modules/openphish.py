"""OpenPhish module aligned to SpiderFoot's blacklist behavior."""

from __future__ import annotations

import urllib.parse
import urllib.request
from typing import Any, AsyncIterator

from ..events import ScanEvent
from ..module_base import BaseModule


class OpenPhishModule(BaseModule):
    slug = "openphish"
    name = "OpenPhish"
    watched_types = {"domain", "internet_name", "affiliate_internet_name", "co_hosted_site", "url"}
    produced_types = {
        "blacklisted_internet_name",
        "blacklisted_affiliate_internet_name",
        "blacklisted_cohost",
        "malicious_internet_name",
        "malicious_affiliate_internet_name",
        "malicious_cohost",
        "malicious_url",
        "internet_name",
    }
    requires_key = False

    FEED_URL = "https://www.openphish.com/feed.txt"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        timeout = int(ctx.request.settings.global_settings.get("http_timeout", 15) or 15)
        feed = self._fetch_feed(timeout, ctx)
        if feed is None:
            return

        for child in self._events_from_feed(feed, event, ctx):
            yield child

    def _fetch_feed(self, timeout: int, ctx) -> set[str] | None:
        request = urllib.request.Request(
            self.FEED_URL,
            headers={"Accept": "text/plain", "User-Agent": "CTI Engine"},
            method="GET",
        )
        ctx.info("Fetching OpenPhish feed.", self.slug)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec - fixed provider URL
                status = int(getattr(response, "status", 200) or 200)
                content = response.read().decode("utf-8", errors="replace")
        except Exception as exc:
            ctx.warning(f"OpenPhish request failed: {exc}", self.slug)
            return None

        if status != 200:
            ctx.warning(f"OpenPhish returned HTTP {status}.", self.slug)
            return None

        return self._parse_feed(content)

    def _parse_feed(self, content: str) -> set[str]:
        hosts: set[str] = set()
        for line in content.splitlines():
            row = line.strip().lower()
            if not row.startswith("http"):
                continue
            parts = row.split("/")
            if len(parts) < 3:
                continue
            host = parts[2].split(":")[0].strip()
            if host and "." in host:
                hosts.add(host)
        return hosts

    def _events_from_feed(self, feed_hosts: set[str], parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        if parent_event.event_type == "url":
            return self._url_events(feed_hosts, parent_event, ctx)

        event_types = self._host_event_pair(parent_event.event_type, ctx)
        if event_types is None:
            return []

        indicator = str(parent_event.value or "").strip().lower()
        if not indicator or indicator not in feed_hosts:
            return []

        malicious_type, blacklisted_type = event_types
        detail = {
            "indicator": parent_event.value,
            "source_url": self.FEED_URL,
        }
        value = f"OpenPhish [{parent_event.value}]"
        return [
            ScanEvent(
                event_type=malicious_type,
                value=value,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=95,
                visibility=100,
                risk_score=90,
                tags=["openphish", "phishing", "malicious"],
                raw_payload=detail,
            ),
            ScanEvent(
                event_type=blacklisted_type,
                value=value,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=95,
                visibility=100,
                risk_score=85,
                tags=["openphish", "phishing", "blacklist"],
                raw_payload=detail,
            ),
        ]

    def _host_event_pair(self, event_type: str, ctx) -> tuple[str, str] | None:
        normalized = str(event_type or "").strip().lower()
        settings = ctx.module_settings_for(self.slug)

        if normalized in {"domain", "internet_name"}:
            return ("malicious_internet_name", "blacklisted_internet_name")

        if normalized == "affiliate_internet_name":
            if not self._truthy(settings.get("checkaffiliates", True)):
                return None
            return ("malicious_affiliate_internet_name", "blacklisted_affiliate_internet_name")

        if normalized == "co_hosted_site":
            if not self._truthy(settings.get("checkcohosts", True)):
                return None
            return ("malicious_cohost", "blacklisted_cohost")

        return None

    def _url_events(self, feed_hosts: set[str], parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        host = self._hostname(parent_event.value)
        if not host or host not in feed_hosts:
            return []

        return [
            ScanEvent(
                event_type="malicious_url",
                value=parent_event.value,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=95,
                visibility=100,
                risk_score=90,
                tags=["openphish", "phishing", "malicious"],
                raw_payload={"source_url": self.FEED_URL},
            ),
            ScanEvent(
                event_type="internet_name",
                value=host,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=80,
                visibility=100,
                risk_score=10,
                tags=["openphish", "hostname"],
                raw_payload={"source_url": parent_event.value},
            ),
        ]

    def _hostname(self, url_value: str) -> str:
        try:
            parsed = urllib.parse.urlparse(url_value)
        except Exception:
            return ""
        return str(parsed.hostname or "").strip().lower()

    def _truthy(self, value: Any) -> bool:
        return str(value).strip().lower() not in {"0", "false", "no", "off", ""}
