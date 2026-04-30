"""Whoisology module for the first-party CTI engine."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, AsyncIterator

from ..events import ScanEvent
from ..module_base import BaseModule
from ..targets import DOMAIN_RX


class WhoisologyModule(BaseModule):
    slug = "whoisology"
    name = "Whoisology"
    watched_types = {"email"}
    produced_types = {"affiliate_internet_name", "affiliate_domain_name"}
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
        email: str,
        api_key: str,
        base_url: str,
        timeout: int,
        ctx,
    ) -> list[dict[str, Any]] | None:
        params = {
            "auth": api_key,
            "request": "flat",
            "field": "email",
            "value": email,
            "level": "Registrant|Admin|Tec|Billing|Other",
        }
        endpoint = f"{base_url.rstrip('/')}?{urllib.parse.urlencode(params)}"
        headers = {
            "Accept": "application/json",
            "User-Agent": "CTI Engine",
        }
        ctx.info(f"Fetching Whoisology data for {email}.", self.slug)
        request = urllib.request.Request(endpoint, headers=headers, method="GET")

        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec - fixed provider URL
                status = int(getattr(response, "status", 200) or 200)
                content = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                ctx.info(f"Whoisology has no data for {email}.", self.slug)
                return None
            if exc.code == 429:
                ctx.error("Your request to Whoisology was throttled.", self.slug)
                return None
            if exc.code in (400, 401, 403, 500):
                ctx.error("Whoisology rejected the API key or usage limit was exceeded.", self.slug)
                return None
            ctx.warning(f"Whoisology request failed for {email}: HTTP {exc.code}", self.slug)
            return None
        except Exception as exc:
            ctx.warning(f"Whoisology request failed for {email}: {exc}", self.slug)
            return None

        if status >= 400:
            ctx.warning(f"Whoisology returned HTTP {status} for {email}.", self.slug)
            return None

        try:
            decoded = json.loads(content)
        except json.JSONDecodeError as exc:
            ctx.error(f"Whoisology returned invalid JSON: {exc}", self.slug)
            return None

        if not isinstance(decoded, dict):
            return None

        domains = decoded.get("domains")
        if domains is None:
            status_reason = str(decoded.get("status_reason", "Unknown") or "Unknown")
            ctx.warning(f"Whoisology returned an unexpected response: {status_reason}", self.slug)
            return None

        if not isinstance(domains, list) or not domains:
            ctx.info(f"Whoisology returned no domains for {email}.", self.slug)
            return None

        return [row for row in domains if isinstance(row, dict)]

    def _events_from_payload(
        self,
        payload: list[dict[str, Any]],
        parent_event: ScanEvent,
        ctx,
    ) -> list[ScanEvent]:
        events: list[ScanEvent] = []
        seen: set[str] = set()
        for row in payload:
            domain_name = str(row.get("domain_name", "") or "").strip().lower().rstrip(".")
            if not domain_name or domain_name in seen:
                continue
            seen.add(domain_name)

            events.append(ScanEvent(
                event_type="affiliate_internet_name",
                value=domain_name,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=78,
                visibility=100,
                risk_score=8,
                tags=["whoisology", "reverse_whois", "email"],
                raw_payload={"source_email": parent_event.value},
            ))
            if DOMAIN_RX.match(domain_name):
                events.append(ScanEvent(
                    event_type="affiliate_domain_name",
                    value=domain_name,
                    source_module=self.slug,
                    root_target=ctx.root_target,
                    parent_event_id=parent_event.event_id,
                    confidence=78,
                    visibility=100,
                    risk_score=8,
                    tags=["whoisology", "reverse_whois", "email", "domain"],
                    raw_payload={"source_email": parent_event.value},
                ))
        return events
