"""Whoxy module for the first-party CTI engine."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, AsyncIterator

from ..events import ScanEvent
from ..module_base import BaseModule


class WhoxyModule(BaseModule):
    slug = "whoxy"
    name = "Whoxy"
    watched_types = {"domain"}
    produced_types = {"whois_record", "internet_name"}
    requires_key = True

    DEFAULT_BASE_URL = "https://api.whoxy.com"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        api_config = ctx.api_config_for(self.slug)
        api_key = str(api_config.get("api_key", "")).strip()
        if not api_key:
            ctx.error("Whoxy module requires an API key.", self.slug)
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
        endpoint = f"{base_url.rstrip('/')}?{urllib.parse.urlencode({'key': api_key, 'whois': domain})}"
        headers = {
            "Accept": "application/json",
            "User-Agent": "CTI Engine",
        }
        ctx.info(f"Fetching Whoxy data for {domain}.", self.slug)
        request = urllib.request.Request(endpoint, headers=headers, method="GET")

        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec - fixed provider URL
                status = int(getattr(response, "status", 200) or 200)
                content = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                ctx.info(f"Whoxy has no data for {domain}.", self.slug)
                return None
            if exc.code == 429:
                ctx.error("Your request to Whoxy was throttled.", self.slug)
                return None
            if exc.code in (401, 403):
                ctx.error("Whoxy rejected the API key or access token.", self.slug)
                return None
            ctx.warning(f"Whoxy request failed for {domain}: HTTP {exc.code}", self.slug)
            return None
        except Exception as exc:
            ctx.warning(f"Whoxy request failed for {domain}: {exc}", self.slug)
            return None

        if status >= 400:
            ctx.warning(f"Whoxy returned HTTP {status} for {domain}.", self.slug)
            return None

        try:
            decoded = json.loads(content)
        except json.JSONDecodeError as exc:
            ctx.error(f"Whoxy returned invalid JSON: {exc}", self.slug)
            return None

        if not isinstance(decoded, dict):
            return None

        status_code = int(decoded.get("status", 1) or 1)
        status_reason = str(decoded.get("status_reason", "") or "").strip().lower()
        if status_code == 0 or "not found" in status_reason:
            ctx.info(f"Whoxy has no WHOIS record for {domain}.", self.slug)
            return None

        return decoded

    def _events_from_payload(
        self,
        payload: dict[str, Any],
        parent_event: ScanEvent,
        ctx,
    ) -> list[ScanEvent]:
        registrar = str(payload.get("registrar_name", "") or "Unknown").strip()
        created = str(payload.get("create_date", "") or "").strip()
        expires = str(payload.get("expiry_date", "") or "").strip()
        nameservers = payload.get("name_servers") or []

        summary_parts = [f"Domain {parent_event.value}: Registrar {registrar}"]
        if created:
            summary_parts.append(f"Created {created}")
        if expires:
            summary_parts.append(f"Expires {expires}")

        events: list[ScanEvent] = [
            ScanEvent(
                event_type="whois_record",
                value="; ".join(summary_parts),
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=86,
                visibility=100,
                risk_score=10,
                tags=["whois", "whoxy", "domain"],
                raw_payload={
                    "registrar_name": registrar,
                    "create_date": created,
                    "expiry_date": expires,
                },
            )
        ]

        for server in nameservers[:10]:
            server_name = str(server or "").strip().lower().rstrip(".")
            if not server_name:
                continue
            events.append(ScanEvent(
                event_type="internet_name",
                value=server_name,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=78,
                visibility=100,
                risk_score=5,
                tags=["whois", "whoxy", "nameserver"],
                raw_payload={"source_domain": parent_event.value},
            ))

        return events
