"""IPInfo module for the first-party CTI engine."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, AsyncIterator

from ..events import ScanEvent
from ..module_base import BaseModule
from ..targets import DOMAIN_RX


class IpInfoModule(BaseModule):
    slug = "ipinfo"
    name = "IPInfo"
    watched_types = {"ip"}
    produced_types = {
        "raw_rir_data",
        "internet_name",
        "company_name",
        "physical_location",
        "bgp_as_member",
        "vpn_host",
        "proxy_host",
        "tor_exit_node",
    }
    requires_key = True

    DEFAULT_BASE_URL = "https://ipinfo.io"
    ASN_RX = re.compile(r"^AS(\d+)\s+(.*)$", re.I)

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        if event.event_type != "ip":
            ctx.debug(f"IPInfo does not handle event type '{event.event_type}'.", self.slug)
            return

        api_config = ctx.api_config_for(self.slug)
        api_key = str(api_config.get("api_key", "")).strip()
        if not api_key:
            ctx.error("IPInfo module requires an API token.", self.slug)
            return

        base_url = str(api_config.get("base_url", "")).strip() or self.DEFAULT_BASE_URL
        timeout = int(ctx.request.settings.global_settings.get("http_timeout", 15) or 15)
        payload = self._fetch_payload(base_url, api_key, timeout, event.value, ctx)
        if payload is None:
            return

        for child in self._events_from_payload(payload, event, ctx):
            yield child

    def _fetch_payload(self, base_url: str, api_key: str, timeout: int, ip_value: str, ctx) -> dict[str, Any] | None:
        endpoint = f"{base_url.rstrip('/')}/{urllib.parse.quote(ip_value, safe='')}?token={urllib.parse.quote(api_key, safe='')}"
        request = urllib.request.Request(
            endpoint,
            headers={"Accept": "application/json", "Authorization": f"Bearer {api_key}", "User-Agent": "CTI Engine"},
            method="GET",
        )
        ctx.info(f"Fetching IPInfo data for {ip_value}.", self.slug)

        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec - fixed provider URL
                status = int(getattr(response, "status", 200) or 200)
                content = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                ctx.info(f"IPInfo has no data for {ip_value}.", self.slug)
                return None
            if exc.code == 429:
                ctx.error("Your request to IPInfo was throttled.", self.slug)
                return None
            if exc.code in (401, 403):
                ctx.error("IPInfo rejected the API token.", self.slug)
                return None
            ctx.warning(f"IPInfo request failed for {ip_value}: HTTP {exc.code}", self.slug)
            return None
        except Exception as exc:
            ctx.warning(f"IPInfo request failed for {ip_value}: {exc}", self.slug)
            return None

        if status != 200:
            ctx.warning(f"IPInfo returned HTTP {status} for {ip_value}.", self.slug)
            return None

        try:
            return json.loads(content)
        except json.JSONDecodeError as exc:
            ctx.error(f"IPInfo returned invalid JSON: {exc}", self.slug)
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
                tags=["ipinfo", "raw"],
                raw_payload={"ip": parent_event.value},
            ),
        ]

        hostname = str(payload.get("hostname", "") or "").strip().lower()
        if hostname and hostname != parent_event.value and DOMAIN_RX.match(hostname):
            events.append(ScanEvent(
                event_type="internet_name",
                value=hostname,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=76,
                visibility=100,
                risk_score=4,
                tags=["ipinfo", "hostname"],
                raw_payload={"ip": parent_event.value},
            ))

        location = ", ".join(
            part for part in [
                str(payload.get("city", "") or "").strip(),
                str(payload.get("region", "") or "").strip(),
                str(payload.get("country", "") or "").strip(),
            ] if part
        )
        if location:
            events.append(ScanEvent(
                event_type="physical_location",
                value=location,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=78,
                visibility=100,
                risk_score=0,
                tags=["ipinfo", "geo"],
                raw_payload={"ip": parent_event.value},
            ))

        org_text = str(payload.get("org", "") or "").strip()
        if org_text:
            asn_match = self.ASN_RX.match(org_text)
            if asn_match:
                events.append(ScanEvent(
                    event_type="bgp_as_member",
                    value=asn_match.group(1),
                    source_module=self.slug,
                    root_target=ctx.root_target,
                    parent_event_id=parent_event.event_id,
                    confidence=80,
                    visibility=100,
                    risk_score=0,
                    tags=["ipinfo", "asn"],
                    raw_payload={"ip": parent_event.value},
                ))
                company = asn_match.group(2).strip()
            else:
                company = org_text

            if company:
                events.append(ScanEvent(
                    event_type="company_name",
                    value=company,
                    source_module=self.slug,
                    root_target=ctx.root_target,
                    parent_event_id=parent_event.event_id,
                    confidence=76,
                    visibility=100,
                    risk_score=0,
                    tags=["ipinfo", "org"],
                    raw_payload={"ip": parent_event.value},
                ))

        privacy = payload.get("privacy") or {}
        if isinstance(privacy, dict):
            mapping = {
                "vpn": "vpn_host",
                "proxy": "proxy_host",
                "tor": "tor_exit_node",
            }
            for field, event_type in mapping.items():
                if privacy.get(field):
                    events.append(ScanEvent(
                        event_type=event_type,
                        value=parent_event.value,
                        source_module=self.slug,
                        root_target=ctx.root_target,
                        parent_event_id=parent_event.event_id,
                        confidence=80,
                        visibility=100,
                        risk_score=35 if event_type != "tor_exit_node" else 50,
                        tags=["ipinfo", field],
                        raw_payload={"ip": parent_event.value},
                    ))

        return events
