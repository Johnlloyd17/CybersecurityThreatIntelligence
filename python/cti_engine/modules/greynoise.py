"""GreyNoise module for the first-party CTI engine."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, AsyncIterator

from ..events import ScanEvent
from ..module_base import BaseModule


class GreyNoiseModule(BaseModule):
    slug = "greynoise"
    name = "GreyNoise"
    watched_types = {"ip"}
    produced_types = {
        "raw_rir_data",
        "malicious_ip",
        "company_name",
        "physical_location",
        "bgp_as_member",
        "operating_system",
    }
    requires_key = True

    DEFAULT_BASE_URL = "https://api.greynoise.io/v3"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        api_config = ctx.api_config_for(self.slug)
        api_key = str(api_config.get("api_key", "")).strip()
        if not api_key:
            ctx.error("GreyNoise module requires an API key.", self.slug)
            return

        base_url = str(api_config.get("base_url", "")).strip() or self.DEFAULT_BASE_URL
        timeout = int(ctx.request.settings.global_settings.get("http_timeout", 15) or 15)
        payload = self._fetch_payload(base_url, event.value, api_key, timeout, ctx)
        if payload is None:
            return

        for child in self._events_from_payload(payload, event, ctx):
            yield child

    def _fetch_payload(
        self,
        base_url: str,
        value: str,
        api_key: str,
        timeout: int,
        ctx,
    ) -> dict[str, Any] | None:
        endpoint = f"{base_url.rstrip('/')}/community/{urllib.parse.quote(value, safe='')}"
        request = urllib.request.Request(
            endpoint,
            headers={"Accept": "application/json", "User-Agent": "CTI Engine", "key": api_key},
            method="GET",
        )
        ctx.info(f"Fetching GreyNoise data for {value}.", self.slug)

        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec - fixed provider URL
                status = int(getattr(response, "status", 200) or 200)
                content = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                ctx.info(f"GreyNoise has no data for {value}.", self.slug)
                return None
            if exc.code == 429:
                ctx.error("Your request to GreyNoise was throttled.", self.slug)
                return None
            if exc.code in (401, 403):
                ctx.error("GreyNoise rejected the API key or access token.", self.slug)
                return None
            ctx.warning(f"GreyNoise request failed for {value}: HTTP {exc.code}", self.slug)
            return None
        except Exception as exc:
            ctx.warning(f"GreyNoise request failed for {value}: {exc}", self.slug)
            return None

        if status >= 400:
            ctx.warning(f"GreyNoise returned HTTP {status} for {value}.", self.slug)
            return None

        try:
            return json.loads(content)
        except json.JSONDecodeError as exc:
            ctx.error(f"GreyNoise returned invalid JSON: {exc}", self.slug)
            return None

    def _events_from_payload(
        self,
        payload: dict[str, Any],
        parent_event: ScanEvent,
        ctx,
    ) -> list[ScanEvent]:
        events: list[ScanEvent] = [ScanEvent(
            event_type="raw_rir_data",
            value=json.dumps(payload, separators=(",", ":"), sort_keys=True),
            source_module=self.slug,
            root_target=ctx.root_target,
            parent_event_id=parent_event.event_id,
            confidence=85,
            visibility=100,
            risk_score=0,
            tags=["greynoise", "raw"],
            raw_payload={"ip": parent_event.value},
        )]

        classification = str(payload.get("classification", "") or "").strip().lower()
        if classification and classification != "benign":
            events.append(ScanEvent(
                event_type="malicious_ip",
                value=parent_event.value,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=85 if classification == "malicious" else 70,
                visibility=100,
                risk_score=85 if classification == "malicious" else 35,
                tags=["greynoise", classification or "unknown", "scanner"],
                raw_payload={"link": payload.get("link"), "last_seen": payload.get("last_seen")},
            ))

        name = str(payload.get("name", "") or "").strip()
        if name and name.lower() != "unknown":
            events.append(ScanEvent(
                event_type="company_name",
                value=name,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=75,
                visibility=100,
                risk_score=0,
                tags=["greynoise", "name"],
                raw_payload={"ip": parent_event.value},
            ))

        location = self._format_location(payload)
        if location:
            events.append(ScanEvent(
                event_type="physical_location",
                value=location,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=75,
                visibility=100,
                risk_score=0,
                tags=["greynoise", "geo"],
                raw_payload={"ip": parent_event.value},
            ))

        asn = str(payload.get("asn", "") or "").strip().upper()
        if asn.startswith("AS"):
            asn = asn[2:]
        if asn:
            events.append(ScanEvent(
                event_type="bgp_as_member",
                value=asn,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=75,
                visibility=100,
                risk_score=0,
                tags=["greynoise", "asn"],
                raw_payload={"ip": parent_event.value},
            ))

        os_name = str(payload.get("os", "") or "").strip()
        if os_name:
            events.append(ScanEvent(
                event_type="operating_system",
                value=os_name,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=70,
                visibility=100,
                risk_score=0,
                tags=["greynoise", "os"],
                raw_payload={"ip": parent_event.value},
            ))

        return events

    def _format_location(self, payload: dict[str, Any]) -> str:
        parts = [
            str(payload.get("city", "") or "").strip(),
            str(payload.get("country", "") or "").strip(),
        ]
        parts = [part for part in parts if part]
        return ", ".join(parts)
