"""IPQualityScore module for the first-party CTI engine."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, AsyncIterator

from ..events import ScanEvent
from ..module_base import BaseModule


class IpQualityScoreModule(BaseModule):
    slug = "ipqualityscore"
    name = "IPQualityScore"
    watched_types = {"ip", "email", "url", "phone"}
    produced_types = {
        "raw_rir_data",
        "malicious_ip",
        "malicious_url",
        "disposable_email_address",
        "undeliverable_email_address",
        "phone_number_compromised",
        "phone_number_type",
        "vpn_host",
        "proxy_host",
        "tor_exit_node",
    }
    requires_key = True

    DEFAULT_BASE_URL = "https://ipqualityscore.com/api/json"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        api_config = ctx.api_config_for(self.slug)
        api_key = str(api_config.get("api_key", "")).strip()
        if not api_key:
            ctx.error("IPQualityScore module requires an API key.", self.slug)
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
        type_map = {"ip": "ip", "email": "email", "url": "url", "phone": "phone"}
        endpoint_type = type_map.get(event.event_type)
        if endpoint_type is None:
            ctx.debug(f"IPQualityScore does not handle event type '{event.event_type}'.", self.slug)
            return None

        endpoint = f"{base_url.rstrip('/')}/{endpoint_type}/{urllib.parse.quote(api_key, safe='')}/{urllib.parse.quote(event.value, safe='')}"
        request = urllib.request.Request(
            endpoint,
            headers={"Accept": "application/json", "User-Agent": "CTI Engine"},
            method="GET",
        )
        ctx.info(f"Fetching IPQualityScore data for {event.value}.", self.slug)

        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec - fixed provider URL
                status = int(getattr(response, "status", 200) or 200)
                content = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                ctx.error("Your request to IPQualityScore was throttled.", self.slug)
                return None
            if exc.code in (401, 403):
                ctx.error("IPQualityScore rejected the API key.", self.slug)
                return None
            ctx.warning(f"IPQualityScore request failed for {event.value}: HTTP {exc.code}", self.slug)
            return None
        except Exception as exc:
            ctx.warning(f"IPQualityScore request failed for {event.value}: {exc}", self.slug)
            return None

        if status != 200:
            ctx.warning(f"IPQualityScore returned HTTP {status} for {event.value}.", self.slug)
            return None

        try:
            decoded = json.loads(content)
        except json.JSONDecodeError as exc:
            ctx.error(f"IPQualityScore returned invalid JSON: {exc}", self.slug)
            return None

        if not bool(decoded.get("success", True)):
            ctx.warning(f"IPQualityScore returned an error for {event.value}: {decoded.get('message', 'unknown error')}", self.slug)
            return None
        return decoded

    def _events_from_payload(self, payload: dict[str, Any], parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        events: list[ScanEvent] = [
            ScanEvent(
                event_type="raw_rir_data",
                value=json.dumps(payload, separators=(",", ":"), sort_keys=True),
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=80,
                visibility=100,
                risk_score=0,
                tags=["ipqualityscore", "raw"],
                raw_payload={"query": parent_event.value},
            ),
        ]

        fraud_score = int(payload.get("fraud_score", 0) or 0)

        if parent_event.event_type == "ip":
            if fraud_score >= 75:
                events.append(ScanEvent(
                    event_type="malicious_ip",
                    value=parent_event.value,
                    source_module=self.slug,
                    root_target=ctx.root_target,
                    parent_event_id=parent_event.event_id,
                    confidence=min(95, 60 + fraud_score // 2),
                    visibility=100,
                    risk_score=fraud_score,
                    tags=["ipqualityscore", "fraud"],
                    raw_payload={"fraud_score": fraud_score},
                ))
            for field, event_type in {"vpn": "vpn_host", "proxy": "proxy_host", "tor": "tor_exit_node"}.items():
                if payload.get(field):
                    events.append(ScanEvent(
                        event_type=event_type,
                        value=parent_event.value,
                        source_module=self.slug,
                        root_target=ctx.root_target,
                        parent_event_id=parent_event.event_id,
                        confidence=80,
                        visibility=100,
                        risk_score=max(fraud_score, 30),
                        tags=["ipqualityscore", field],
                        raw_payload={"fraud_score": fraud_score},
                    ))
            return events

        if parent_event.event_type == "url":
            if fraud_score >= 70 or payload.get("unsafe") or payload.get("phishing") or payload.get("malware"):
                events.append(ScanEvent(
                    event_type="malicious_url",
                    value=parent_event.value,
                    source_module=self.slug,
                    root_target=ctx.root_target,
                    parent_event_id=parent_event.event_id,
                    confidence=min(95, 60 + fraud_score // 2),
                    visibility=100,
                    risk_score=max(fraud_score, 70),
                    tags=["ipqualityscore", "url", "fraud"],
                    raw_payload={"fraud_score": fraud_score},
                ))
            return events

        if parent_event.event_type == "email":
            if payload.get("disposable"):
                events.append(ScanEvent(
                    event_type="disposable_email_address",
                    value=parent_event.value,
                    source_module=self.slug,
                    root_target=ctx.root_target,
                    parent_event_id=parent_event.event_id,
                    confidence=85,
                    visibility=100,
                    risk_score=max(fraud_score, 40),
                    tags=["ipqualityscore", "email", "disposable"],
                    raw_payload={"fraud_score": fraud_score},
                ))
            if payload.get("valid") is False:
                events.append(ScanEvent(
                    event_type="undeliverable_email_address",
                    value=parent_event.value,
                    source_module=self.slug,
                    root_target=ctx.root_target,
                    parent_event_id=parent_event.event_id,
                    confidence=85,
                    visibility=100,
                    risk_score=max(fraud_score, 25),
                    tags=["ipqualityscore", "email", "invalid"],
                    raw_payload={"fraud_score": fraud_score},
                ))
            return events

        if parent_event.event_type == "phone":
            phone_type = str(payload.get("line_type", "") or payload.get("carrier", "") or "").strip()
            if phone_type:
                events.append(ScanEvent(
                    event_type="phone_number_type",
                    value=phone_type,
                    source_module=self.slug,
                    root_target=ctx.root_target,
                    parent_event_id=parent_event.event_id,
                    confidence=75,
                    visibility=100,
                    risk_score=0,
                    tags=["ipqualityscore", "phone"],
                    raw_payload={"query": parent_event.value},
                ))
            if fraud_score >= 75:
                events.append(ScanEvent(
                    event_type="phone_number_compromised",
                    value=parent_event.value,
                    source_module=self.slug,
                    root_target=ctx.root_target,
                    parent_event_id=parent_event.event_id,
                    confidence=min(95, 60 + fraud_score // 2),
                    visibility=100,
                    risk_score=fraud_score,
                    tags=["ipqualityscore", "phone", "fraud"],
                    raw_payload={"fraud_score": fraud_score},
                ))
        return events
