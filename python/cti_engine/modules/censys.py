"""Censys module for the first-party CTI engine."""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, AsyncIterator

from ..events import ScanEvent
from ..module_base import BaseModule


class CensysModule(BaseModule):
    slug = "censys"
    name = "Censys"
    watched_types = {"domain", "ip"}
    produced_types = {
        "raw_rir_data",
        "ip",
        "open_port",
        "software_used",
        "bgp_as_member",
        "operating_system",
        "physical_location",
    }
    requires_key = True

    DEFAULT_BASE_URL = "https://search.censys.io/api/v2"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        api_config = ctx.api_config_for(self.slug)
        api_key = str(api_config.get("api_key", "")).strip()
        if not api_key:
            ctx.error("Censys module requires API credentials.", self.slug)
            return

        auth_header = self._basic_auth(api_key)
        if auth_header is None:
            ctx.error("Censys credentials must be stored as 'API_ID:API_SECRET'.", self.slug)
            return

        base_url = str(api_config.get("base_url", "")).strip() or self.DEFAULT_BASE_URL
        timeout = int(ctx.request.settings.global_settings.get("http_timeout", 15) or 15)
        payload = self._fetch_payload(base_url, auth_header, timeout, event, ctx)
        if payload is None:
            return

        for child in self._events_from_payload(payload, event, ctx):
            yield child

    def _basic_auth(self, raw_key: str) -> str | None:
        if ":" not in raw_key:
            return None
        encoded = base64.b64encode(raw_key.encode("utf-8")).decode("ascii")
        return f"Basic {encoded}"

    def _fetch_payload(
        self,
        base_url: str,
        auth_header: str,
        timeout: int,
        event: ScanEvent,
        ctx,
    ) -> dict[str, Any] | None:
        if event.event_type == "ip":
            endpoint = f"{base_url.rstrip('/')}/hosts/{urllib.parse.quote(event.value, safe='')}"
            label = "host"
        elif event.event_type == "domain":
            query = urllib.parse.urlencode({"q": event.value, "per_page": 25})
            endpoint = f"{base_url.rstrip('/')}/hosts/search?{query}"
            label = "host search"
        else:
            ctx.debug(f"Censys does not handle event type '{event.event_type}'.", self.slug)
            return None

        request = urllib.request.Request(
            endpoint,
            headers={
                "Accept": "application/json",
                "Authorization": auth_header,
                "User-Agent": "CTI Engine",
            },
            method="GET",
        )
        ctx.info(f"Fetching Censys {label} data for {event.value}.", self.slug)

        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec - fixed provider URL
                status = int(getattr(response, "status", 200) or 200)
                content = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                ctx.info(f"Censys has no data for {event.value}.", self.slug)
                return None
            if exc.code == 429:
                ctx.error("Your request to Censys was throttled.", self.slug)
                return None
            if exc.code in (401, 403):
                ctx.error("Censys rejected the configured credentials.", self.slug)
                return None
            ctx.warning(f"Censys request failed for {event.value}: HTTP {exc.code}", self.slug)
            return None
        except Exception as exc:
            ctx.warning(f"Censys request failed for {event.value}: {exc}", self.slug)
            return None

        if status != 200:
            ctx.warning(f"Censys returned HTTP {status} for {event.value}.", self.slug)
            return None

        try:
            return json.loads(content)
        except json.JSONDecodeError as exc:
            ctx.error(f"Censys returned invalid JSON: {exc}", self.slug)
            return None

    def _events_from_payload(
        self,
        payload: dict[str, Any],
        parent_event: ScanEvent,
        ctx,
    ) -> list[ScanEvent]:
        if parent_event.event_type == "domain":
            return self._events_from_domain_search(payload, parent_event, ctx)
        return self._events_from_host_payload(payload, parent_event, ctx)

    def _events_from_domain_search(
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
                tags=["censys", "raw", "search"],
                raw_payload={"query": parent_event.value},
            ),
        ]
        hits = payload.get("result", {}).get("hits") or []
        seen: set[str] = set()
        for row in hits[:25]:
            if not isinstance(row, dict):
                continue
            ip_value = str(row.get("ip", "") or "").strip()
            if not ip_value or ip_value in seen:
                continue
            seen.add(ip_value)
            events.append(ScanEvent(
                event_type="ip",
                value=ip_value,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=80,
                visibility=100,
                risk_score=5,
                tags=["censys", "search", "ip"],
                raw_payload={"domain": parent_event.value},
            ))
        return events

    def _events_from_host_payload(
        self,
        payload: dict[str, Any],
        parent_event: ScanEvent,
        ctx,
    ) -> list[ScanEvent]:
        result = payload.get("result") if isinstance(payload.get("result"), dict) else payload
        events: list[ScanEvent] = [
            ScanEvent(
                event_type="raw_rir_data",
                value=json.dumps(result, separators=(",", ":"), sort_keys=True),
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=82,
                visibility=100,
                risk_score=0,
                tags=["censys", "raw", "host"],
                raw_payload={"ip": parent_event.value},
            ),
        ]

        location = result.get("location") or {}
        location_text = ", ".join(
            part for part in [
                str(location.get("city", "") or "").strip(),
                str(location.get("province", "") or "").strip(),
                str(location.get("country", "") or "").strip(),
            ] if part
        )
        if location_text:
            events.append(ScanEvent(
                event_type="physical_location",
                value=location_text,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=78,
                visibility=100,
                risk_score=0,
                tags=["censys", "geo"],
                raw_payload={"ip": parent_event.value},
            ))

        asn_payload = result.get("autonomous_system") or {}
        asn_value = str(asn_payload.get("asn", "") or "").strip()
        if asn_value:
            events.append(ScanEvent(
                event_type="bgp_as_member",
                value=asn_value,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=80,
                visibility=100,
                risk_score=0,
                tags=["censys", "asn"],
                raw_payload={"ip": parent_event.value},
            ))

        services = result.get("services") or []
        seen_ports: set[str] = set()
        seen_products: set[str] = set()
        for row in services[:40]:
            if not isinstance(row, dict):
                continue
            port = row.get("port")
            if port is not None:
                port_value = f"{parent_event.value}:{int(port)}"
                if port_value not in seen_ports:
                    seen_ports.add(port_value)
                    events.append(ScanEvent(
                        event_type="open_port",
                        value=port_value,
                        source_module=self.slug,
                        root_target=ctx.root_target,
                        parent_event_id=parent_event.event_id,
                        confidence=88,
                        visibility=100,
                        risk_score=5,
                        tags=["censys", "port"],
                        raw_payload={"ip": parent_event.value, "port": int(port)},
                    ))

            service_name = str(row.get("service_name", row.get("extended_service_name", "")) or "").strip()
            if service_name and service_name not in seen_products:
                seen_products.add(service_name)
                events.append(ScanEvent(
                    event_type="software_used",
                    value=service_name,
                    source_module=self.slug,
                    root_target=ctx.root_target,
                    parent_event_id=parent_event.event_id,
                    confidence=78,
                    visibility=100,
                    risk_score=0,
                    tags=["censys", "service"],
                    raw_payload={"ip": parent_event.value},
                ))

            os_text = str(row.get("operating_system", "") or "").strip()
            if os_text:
                events.append(ScanEvent(
                    event_type="operating_system",
                    value=os_text,
                    source_module=self.slug,
                    root_target=ctx.root_target,
                    parent_event_id=parent_event.event_id,
                    confidence=76,
                    visibility=100,
                    risk_score=0,
                    tags=["censys", "os"],
                    raw_payload={"ip": parent_event.value},
                ))
        return events
