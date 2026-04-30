"""ipregistry module for the first-party CTI engine."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, AsyncIterator

from ..events import ScanEvent
from ..module_base import BaseModule


class IpRegistryModule(BaseModule):
    slug = "ipregistry"
    name = "ipregistry"
    watched_types = {"ip"}
    produced_types = {
        "raw_rir_data",
        "company_name",
        "physical_location",
        "bgp_as_member",
        "vpn_host",
        "proxy_host",
        "tor_exit_node",
    }
    requires_key = True

    DEFAULT_BASE_URL = "https://api.ipregistry.co"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        if event.event_type != "ip":
            ctx.debug(f"ipregistry does not handle event type '{event.event_type}'.", self.slug)
            return

        api_config = ctx.api_config_for(self.slug)
        api_key = str(api_config.get("api_key", "")).strip()
        if not api_key:
            ctx.error("ipregistry module requires an API key.", self.slug)
            return

        base_url = str(api_config.get("base_url", "")).strip() or self.DEFAULT_BASE_URL
        timeout = int(ctx.request.settings.global_settings.get("http_timeout", 15) or 15)
        payload = self._fetch_payload(base_url, api_key, timeout, event.value, ctx)
        if payload is None:
            return

        for child in self._events_from_payload(payload, event, ctx):
            yield child

    def _fetch_payload(self, base_url: str, api_key: str, timeout: int, ip_value: str, ctx) -> dict[str, Any] | None:
        endpoint = f"{base_url.rstrip('/')}/{urllib.parse.quote(ip_value, safe='')}?key={urllib.parse.quote(api_key, safe='')}"
        request = urllib.request.Request(
            endpoint,
            headers={"Accept": "application/json", "User-Agent": "CTI Engine"},
            method="GET",
        )
        ctx.info(f"Fetching ipregistry data for {ip_value}.", self.slug)

        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec - fixed provider URL
                status = int(getattr(response, "status", 200) or 200)
                content = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                ctx.info(f"ipregistry has no data for {ip_value}.", self.slug)
                return None
            if exc.code == 429:
                ctx.error("Your request to ipregistry was throttled.", self.slug)
                return None
            if exc.code in (401, 403):
                ctx.error("ipregistry rejected the API key.", self.slug)
                return None
            ctx.warning(f"ipregistry request failed for {ip_value}: HTTP {exc.code}", self.slug)
            return None
        except Exception as exc:
            ctx.warning(f"ipregistry request failed for {ip_value}: {exc}", self.slug)
            return None

        if status != 200:
            ctx.warning(f"ipregistry returned HTTP {status} for {ip_value}.", self.slug)
            return None

        try:
            return json.loads(content)
        except json.JSONDecodeError as exc:
            ctx.error(f"ipregistry returned invalid JSON: {exc}", self.slug)
            return None

    def _events_from_payload(self, payload: dict[str, Any], parent_event: ScanEvent, ctx) -> list[ScanEvent]:
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
                tags=["ipregistry", "raw"],
                raw_payload={"ip": parent_event.value},
            ),
        ]

        connection = payload.get("connection") or {}
        location = payload.get("location") or {}
        security = payload.get("security") or {}

        organization = str(connection.get("organization", "") or "").strip()
        if organization:
            events.append(ScanEvent(
                event_type="company_name",
                value=organization,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=78,
                visibility=100,
                risk_score=0,
                tags=["ipregistry", "org"],
                raw_payload={"ip": parent_event.value},
            ))

        asn_value = str(connection.get("asn", "") or "").strip()
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
                tags=["ipregistry", "asn"],
                raw_payload={"ip": parent_event.value},
            ))

        location_text = ", ".join(
            part for part in [
                str(location.get("city", "") or "").strip(),
                str((location.get("country") or {}).get("name", "") or "").strip(),
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
                tags=["ipregistry", "geo"],
                raw_payload={"ip": parent_event.value},
            ))

        mapping = {
            "is_vpn": "vpn_host",
            "is_proxy": "proxy_host",
            "is_tor_exit": "tor_exit_node",
        }
        for field, event_type in mapping.items():
            if security.get(field):
                events.append(ScanEvent(
                    event_type=event_type,
                    value=parent_event.value,
                    source_module=self.slug,
                    root_target=ctx.root_target,
                    parent_event_id=parent_event.event_id,
                    confidence=80,
                    visibility=100,
                    risk_score=35 if event_type != "tor_exit_node" else 50,
                    tags=["ipregistry", field],
                    raw_payload={"ip": parent_event.value},
                ))

        return events
