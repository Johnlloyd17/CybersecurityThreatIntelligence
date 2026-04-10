"""VirusTotal module skeleton with real request/parsing flow.

The network path is intentionally lightweight so the engine foundation remains
standard-library only. During tests we validate the parsing path, not live HTTP.
"""

from __future__ import annotations

import json
import time
import urllib.parse
import urllib.request
from typing import Any, AsyncIterator

from ..events import ScanEvent
from ..module_base import BaseModule


class VirusTotalModule(BaseModule):
    slug = "virustotal"
    name = "VirusTotal"
    watched_types = {"domain", "ip", "url", "hash"}
    produced_types = {
        "internet_name",
        "linked_url_internal",
        "malicious_domain",
        "malicious_ip",
    }
    requires_key = True

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        api_config = ctx.api_config_for(self.slug)
        api_key = str(api_config.get("api_key", "")).strip()
        if not api_key:
            ctx.error("VirusTotal module requires an API key.", self.slug)
            return

        payload = self._fetch_payload(event.event_type, event.value, api_key, ctx)
        if payload is None:
            return

        for child in self._events_from_payload(payload, event, ctx):
            yield child

    def _fetch_payload(
        self,
        event_type: str,
        value: str,
        api_key: str,
        ctx,
    ) -> dict[str, Any] | None:
        if event_type == "domain":
            endpoint = "https://www.virustotal.com/vtapi/v2/domain/report"
            params = {"domain": value, "apikey": api_key}
        elif event_type == "ip":
            endpoint = "https://www.virustotal.com/vtapi/v2/ip-address/report"
            params = {"ip": value, "apikey": api_key}
        else:
            ctx.debug(f"VirusTotal module does not yet handle event type '{event_type}'.", self.slug)
            return None

        query = urllib.parse.urlencode(params)
        request_url = f"{endpoint}?{query}"
        timeout = int(ctx.request.settings.global_settings.get("http_timeout", 15) or 15)
        ctx.info(f"Fetching VirusTotal data for {value}.", self.slug)

        request = urllib.request.Request(
            request_url,
            headers={"User-Agent": "CTI Engine"},
            method="GET",
        )

        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec - fixed provider URL
                if getattr(response, "status", None) == 204:
                    ctx.error("Your request to VirusTotal was throttled.", self.slug)
                    return None
                content = response.read().decode("utf-8", errors="replace")
        except Exception as exc:
            ctx.warning(f"VirusTotal request failed for {value}: {exc}", self.slug)
            return None

        public_key = self._is_public_key(ctx)
        if public_key:
            time.sleep(15)

        try:
            return json.loads(content)
        except json.JSONDecodeError as exc:
            ctx.error(f"VirusTotal returned invalid JSON: {exc}", self.slug)
            return None

    def _is_public_key(self, ctx) -> bool:
        settings = ctx.module_settings_for(self.slug)
        raw = settings.get("public_key", settings.get("publicapi", True))
        return str(raw).strip().lower() in {"1", "true", "yes", "on"}

    def _events_from_payload(
        self,
        payload: dict[str, Any],
        parent_event: ScanEvent,
        ctx,
    ) -> list[ScanEvent]:
        events: list[ScanEvent] = []

        detected_urls = payload.get("detected_urls") or []
        if detected_urls:
            events.append(ScanEvent(
                event_type="malicious_domain" if parent_event.event_type == "domain" else "malicious_ip",
                value=parent_event.value,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=90,
                visibility=100,
                risk_score=80,
                tags=["virustotal", "malicious"],
                raw_payload={"detected_urls_count": len(detected_urls)},
            ))

        for url_row in detected_urls:
            url_value = str(url_row.get("url", "")).strip()
            if not url_value:
                continue
            events.append(ScanEvent(
                event_type="linked_url_internal",
                value=url_value,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=80,
                visibility=100,
                risk_score=25,
                tags=["virustotal", "url"],
                raw_payload={"positives": url_row.get("positives")},
            ))

        for name in list(payload.get("subdomains") or []) + list(payload.get("domain_siblings") or []):
            sibling = str(name).strip().lower()
            if not sibling:
                continue
            events.append(ScanEvent(
                event_type="internet_name",
                value=sibling,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=70,
                visibility=100,
                risk_score=10,
                tags=["virustotal", "domain"],
                raw_payload={"parent": parent_event.value},
            ))

        return events

