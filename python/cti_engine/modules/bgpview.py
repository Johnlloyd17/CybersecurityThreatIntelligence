"""BGPView module aligned to SpiderFoot's core behavior."""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, AsyncIterator

from ..events import ScanEvent
from ..module_base import BaseModule


class BgpViewModule(BaseModule):
    slug = "bgpview"
    name = "BGPView"
    watched_types = {"domain", "ip", "ipv6", "bgp_as_member", "netblock_member", "netblockv6_member"}
    produced_types = {"ip", "raw_rir_data", "bgp_as_member", "netblock_member", "netblockv6_member", "physical_address"}
    requires_key = False

    DEFAULT_BASE_URL = "https://api.bgpview.io"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        if event.event_type == "domain":
            child = self._resolve_domain(event, ctx)
            if child is not None:
                yield child
            return

        timeout = int(ctx.request.settings.global_settings.get("http_timeout", 15) or 15)

        if event.event_type in {"ip", "ipv6"}:
            payload = self._request_json(f"/ip/{urllib.parse.quote(event.value, safe='')}", timeout, event.value, ctx)
            if payload is None:
                return
            for child in self._events_from_ip_payload(payload, event, ctx):
                yield child
            return

        if event.event_type == "bgp_as_member":
            asn_value = str(event.value).strip().upper().removeprefix("AS")
            payload = self._request_json(f"/asn/{urllib.parse.quote(asn_value, safe='')}", timeout, event.value, ctx)
            if payload is None:
                return
            for child in self._events_from_owner_payload(payload, event, ctx):
                yield child
            return

        if event.event_type in {"netblock_member", "netblockv6_member"}:
            payload = self._request_json(f"/prefix/{urllib.parse.quote(event.value, safe='')}", timeout, event.value, ctx)
            if payload is None:
                return
            for child in self._events_from_owner_payload(payload, event, ctx):
                yield child
            return

        ctx.debug(f"BGPView does not handle event type '{event.event_type}'.", self.slug)

    def _resolve_domain(self, event: ScanEvent, ctx) -> ScanEvent | None:
        try:
            ip_value = socket.gethostbyname(event.value)
        except OSError:
            ctx.info(f"BGPView could not resolve {event.value}.", self.slug)
            return None

        if ip_value == event.value:
            return None

        return ScanEvent(
            event_type="ip",
            value=ip_value,
            source_module=self.slug,
            root_target=ctx.root_target,
            parent_event_id=event.event_id,
            confidence=90,
            visibility=100,
            risk_score=0,
            tags=["bgpview", "resolved"],
            raw_payload={"domain": event.value},
        )

    def _request_json(self, path: str, timeout: int, value: str, ctx) -> dict[str, Any] | None:
        endpoint = f"{self.DEFAULT_BASE_URL.rstrip('/')}{path}"
        request = urllib.request.Request(
            endpoint,
            headers={"Accept": "application/json", "User-Agent": "CTI Engine"},
            method="GET",
        )
        ctx.info(f"Fetching BGPView data for {value}.", self.slug)

        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec - fixed provider URL
                status = int(getattr(response, "status", 200) or 200)
                content = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                ctx.info(f"BGPView has no data for {value}.", self.slug)
                return None
            if exc.code == 429:
                ctx.error("Your request to BGPView was throttled.", self.slug)
                return None
            ctx.warning(f"BGPView request failed for {value}: HTTP {exc.code}", self.slug)
            return None
        except Exception as exc:
            ctx.warning(f"BGPView request failed for {value}: {exc}", self.slug)
            return None

        if status != 200:
            ctx.warning(f"BGPView returned HTTP {status} for {value}.", self.slug)
            return None

        try:
            decoded = json.loads(content)
        except json.JSONDecodeError as exc:
            ctx.error(f"BGPView returned invalid JSON: {exc}", self.slug)
            return None

        if str(decoded.get("status", "") or "").strip().lower() != "ok":
            ctx.info(f"BGPView has no data for {value}.", self.slug)
            return None

        return decoded

    def _events_from_ip_payload(self, payload: dict[str, Any], parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
        prefixes = data.get("prefixes") if isinstance(data.get("prefixes"), list) else []

        events: list[ScanEvent] = [
            ScanEvent(
                event_type="raw_rir_data",
                value=json.dumps(data, ensure_ascii=False, sort_keys=True),
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=82,
                visibility=100,
                risk_score=0,
                tags=["bgpview", "raw"],
                raw_payload={"query": parent_event.value},
            )
        ]

        seen_asns: set[str] = set()
        seen_prefixes: set[str] = set()
        for prefix in prefixes:
            if not isinstance(prefix, dict):
                continue

            asn_data = prefix.get("asn") if isinstance(prefix.get("asn"), dict) else {}
            asn_value = str(asn_data.get("asn", "") or "").strip()
            if asn_value and asn_value not in seen_asns:
                seen_asns.add(asn_value)
                events.append(ScanEvent(
                    event_type="bgp_as_member",
                    value=asn_value,
                    source_module=self.slug,
                    root_target=ctx.root_target,
                    parent_event_id=parent_event.event_id,
                    confidence=82,
                    visibility=100,
                    risk_score=0,
                    tags=["bgpview", "asn"],
                    raw_payload={"query": parent_event.value},
                ))

            prefix_value = str(prefix.get("prefix", "") or "").strip()
            if not prefix_value or prefix_value in seen_prefixes:
                continue
            seen_prefixes.add(prefix_value)

            event_type = "netblockv6_member" if ":" in prefix_value else "netblock_member"
            events.append(ScanEvent(
                event_type=event_type,
                value=prefix_value,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=80,
                visibility=100,
                risk_score=0,
                tags=["bgpview", "prefix"],
                raw_payload={"query": parent_event.value},
            ))

        return events

    def _events_from_owner_payload(self, payload: dict[str, Any], parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
        events: list[ScanEvent] = [
            ScanEvent(
                event_type="raw_rir_data",
                value=json.dumps(data, ensure_ascii=False, sort_keys=True),
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=82,
                visibility=100,
                risk_score=0,
                tags=["bgpview", "raw"],
                raw_payload={"query": parent_event.value},
            )
        ]

        owner_address = data.get("owner_address")
        if isinstance(owner_address, list):
            physical = ", ".join(str(part).strip() for part in owner_address if str(part).strip())
            if physical:
                events.append(ScanEvent(
                    event_type="physical_address",
                    value=physical,
                    source_module=self.slug,
                    root_target=ctx.root_target,
                    parent_event_id=parent_event.event_id,
                    confidence=78,
                    visibility=100,
                    risk_score=0,
                    tags=["bgpview", "owner_address"],
                    raw_payload={"query": parent_event.value},
                ))

        return events
