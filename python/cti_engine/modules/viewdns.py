"""ViewDNS.info module for the first-party CTI engine."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, AsyncIterator

from ..events import ScanEvent
from ..module_base import BaseModule
from ..targets import DOMAIN_RX


class ViewDnsModule(BaseModule):
    slug = "viewdns"
    name = "ViewDNS.info"
    watched_types = {"domain", "ip"}
    produced_types = {"raw_rir_data", "raw_dns_records", "internet_name", "ip", "co_hosted_site", "co_hosted_site_domain"}
    requires_key = True

    DEFAULT_BASE_URL = "https://api.viewdns.info"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        api_config = ctx.api_config_for(self.slug)
        api_key = str(api_config.get("api_key", "")).strip()
        if not api_key:
            ctx.error("ViewDNS.info module requires an API key.", self.slug)
            return

        base_url = str(api_config.get("base_url", "")).strip() or self.DEFAULT_BASE_URL
        timeout = int(ctx.request.settings.global_settings.get("http_timeout", 15) or 15)
        payload = self._fetch_payload(base_url, api_key, timeout, event, ctx)
        if payload is None:
            return

        for child in self._events_from_payload(payload, event, ctx):
            yield child

    def _fetch_payload(
        self,
        base_url: str,
        api_key: str,
        timeout: int,
        event: ScanEvent,
        ctx,
    ) -> dict[str, Any] | None:
        if event.event_type == "ip":
            endpoint = f"{base_url.rstrip('/')}/reversedns/?ip={urllib.parse.quote(event.value, safe='')}&apikey={urllib.parse.quote(api_key, safe='')}&output=json"
            label = "reverse DNS"
        elif event.event_type == "domain":
            endpoint = f"{base_url.rstrip('/')}/dnsrecord/?domain={urllib.parse.quote(event.value, safe='')}&recordtype=ANY&apikey={urllib.parse.quote(api_key, safe='')}&output=json"
            label = "DNS records"
        else:
            ctx.debug(f"ViewDNS.info does not handle event type '{event.event_type}'.", self.slug)
            return None

        request = urllib.request.Request(
            endpoint,
            headers={"Accept": "application/json", "User-Agent": "CTI Engine"},
            method="GET",
        )
        ctx.info(f"Fetching ViewDNS.info {label} for {event.value}.", self.slug)

        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec - fixed provider URL
                status = int(getattr(response, "status", 200) or 200)
                content = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                ctx.error("Your request to ViewDNS.info was throttled.", self.slug)
                return None
            if exc.code in (401, 403):
                ctx.error("ViewDNS.info rejected the API key.", self.slug)
                return None
            ctx.warning(f"ViewDNS.info request failed for {event.value}: HTTP {exc.code}", self.slug)
            return None
        except Exception as exc:
            ctx.warning(f"ViewDNS.info request failed for {event.value}: {exc}", self.slug)
            return None

        if status != 200:
            ctx.warning(f"ViewDNS.info returned HTTP {status} for {event.value}.", self.slug)
            return None

        try:
            decoded = json.loads(content)
        except json.JSONDecodeError as exc:
            ctx.error(f"ViewDNS.info returned invalid JSON: {exc}", self.slug)
            return None

        response_payload = decoded.get("response")
        if not isinstance(response_payload, dict):
            ctx.warning("ViewDNS.info returned an unexpected payload.", self.slug)
            return None
        return response_payload

    def _events_from_payload(
        self,
        payload: dict[str, Any],
        parent_event: ScanEvent,
        ctx,
    ) -> list[ScanEvent]:
        events: list[ScanEvent] = [
            ScanEvent(
                event_type="raw_rir_data",
                value=json.dumps(payload, separators=(",", ":"), sort_keys=True),
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=82,
                visibility=100,
                risk_score=0,
                tags=["viewdns", "raw"],
                raw_payload={"query": parent_event.value},
            ),
        ]

        if parent_event.event_type == "domain":
            records = payload.get("records") or []
            if not isinstance(records, list):
                return events
            for record in records[:25]:
                if not isinstance(record, dict):
                    continue
                rrtype = str(record.get("type", "") or "").strip().upper()
                value = str(record.get("data", "") or "").strip().rstrip(".")
                if not value:
                    continue
                events.append(ScanEvent(
                    event_type="raw_dns_records",
                    value=f"{rrtype} {value}",
                    source_module=self.slug,
                    root_target=ctx.root_target,
                    parent_event_id=parent_event.event_id,
                    confidence=76,
                    visibility=100,
                    risk_score=0,
                    tags=["viewdns", "dns", rrtype.lower() or "record"],
                    raw_payload={"domain": parent_event.value},
                ))
                child_type = self._event_type_for_dns_value(value)
                if child_type:
                    events.append(ScanEvent(
                        event_type=child_type,
                        value=value.lower() if child_type != "ip" else value,
                        source_module=self.slug,
                        root_target=ctx.root_target,
                        parent_event_id=parent_event.event_id,
                        confidence=78,
                        visibility=100,
                        risk_score=6,
                        tags=["viewdns", "dns", rrtype.lower() or "record"],
                        raw_payload={"domain": parent_event.value},
                    ))
            return events

        rdns = payload.get("rdns") or []
        if not isinstance(rdns, list):
            return events
        seen: set[str] = set()
        for row in rdns[:25]:
            if not isinstance(row, dict):
                continue
            hostname = str(row.get("name", "") or "").strip().lower().rstrip(".")
            if not hostname or hostname in seen:
                continue
            seen.add(hostname)
            events.append(ScanEvent(
                event_type="co_hosted_site",
                value=hostname,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=80,
                visibility=100,
                risk_score=5,
                tags=["viewdns", "reverse_dns"],
                raw_payload={"ip": parent_event.value},
            ))
            if DOMAIN_RX.match(hostname):
                events.append(ScanEvent(
                    event_type="co_hosted_site_domain",
                    value=hostname,
                    source_module=self.slug,
                    root_target=ctx.root_target,
                    parent_event_id=parent_event.event_id,
                    confidence=80,
                    visibility=100,
                    risk_score=5,
                    tags=["viewdns", "reverse_dns", "domain"],
                    raw_payload={"ip": parent_event.value},
                ))
        return events

    def _event_type_for_dns_value(self, value: str) -> str | None:
        candidate = value.strip().rstrip(".")
        if not candidate:
            return None
        try:
            import ipaddress

            ipaddress.ip_address(candidate)
            return "ip"
        except ValueError:
            pass
        if DOMAIN_RX.match(candidate.lower()):
            return "internet_name"
        return None
