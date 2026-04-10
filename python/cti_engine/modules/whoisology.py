"""Whoisology module for the first-party CTI engine."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, AsyncIterator

from ..events import ScanEvent
from ..module_base import BaseModule


class WhoisologyModule(BaseModule):
    slug = "whoisology"
    name = "Whoisology"
    watched_types = {"domain"}
    produced_types = {"whois_record", "internet_name"}
    requires_key = True

    DEFAULT_BASE_URL = "https://whoisology.com/api"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        api_config = ctx.api_config_for(self.slug)
        api_key = str(api_config.get("api_key", "")).strip()
        if not api_key:
            ctx.error("Whoisology module requires an API key.", self.slug)
            return

        base_url = str(api_config.get("base_url", "")).strip() or self.DEFAULT_BASE_URL
        timeout = int(ctx.request.settings.global_settings.get("http_timeout", 15) or 15)
        payload = self._fetch_payload(event.value, api_key, base_url, timeout, ctx)
        if payload is None:
            return

        for child in self._events_from_payload(payload, event, ctx):
            yield child

    def _fetch_payload(
        self,
        domain: str,
        api_key: str,
        base_url: str,
        timeout: int,
        ctx,
    ) -> dict[str, Any] | None:
        params = {
            "auth": api_key,
            "request": "flat",
            "value": domain,
            "level": "basic",
        }
        endpoint = f"{base_url.rstrip('/')}?{urllib.parse.urlencode(params)}"
        headers = {
            "Accept": "application/json",
            "User-Agent": "CTI Engine",
        }
        ctx.info(f"Fetching Whoisology data for {domain}.", self.slug)
        request = urllib.request.Request(endpoint, headers=headers, method="GET")

        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec - fixed provider URL
                status = int(getattr(response, "status", 200) or 200)
                content = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                ctx.info(f"Whoisology has no data for {domain}.", self.slug)
                return None
            if exc.code == 429:
                ctx.error("Your request to Whoisology was throttled.", self.slug)
                return None
            if exc.code in (401, 403):
                ctx.error("Whoisology rejected the API key or access token.", self.slug)
                return None
            ctx.warning(f"Whoisology request failed for {domain}: HTTP {exc.code}", self.slug)
            return None
        except Exception as exc:
            ctx.warning(f"Whoisology request failed for {domain}: {exc}", self.slug)
            return None

        if status >= 400:
            ctx.warning(f"Whoisology returned HTTP {status} for {domain}.", self.slug)
            return None

        try:
            decoded = json.loads(content)
        except json.JSONDecodeError as exc:
            ctx.error(f"Whoisology returned invalid JSON: {exc}", self.slug)
            return None

        return decoded if isinstance(decoded, dict) else None

    def _events_from_payload(
        self,
        payload: dict[str, Any],
        parent_event: ScanEvent,
        ctx,
    ) -> list[ScanEvent]:
        records = payload.get("result") or payload
        if isinstance(records, dict):
            records = [records]
        if not isinstance(records, list) or not records:
            return []

        related_domains = []
        for record in records[:25]:
            domain_name = str((record or {}).get("domain_name", "") or "").strip().lower()
            if domain_name and domain_name != parent_event.value.strip().lower():
                related_domains.append(domain_name)

        events: list[ScanEvent] = [
            ScanEvent(
                event_type="whois_record",
                value=f"Domain {parent_event.value}: {len(records)} related WHOIS record(s) found",
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=78,
                visibility=100,
                risk_score=min(25, len(records) * 3),
                tags=["whois", "whoisology", "related_domains"],
                raw_payload={"record_count": len(records)},
            )
        ]

        for domain_name in related_domains[:15]:
            events.append(ScanEvent(
                event_type="internet_name",
                value=domain_name,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=74,
                visibility=100,
                risk_score=8,
                tags=["whois", "whoisology", "related_domain"],
                raw_payload={"source_domain": parent_event.value},
            ))

        return events
