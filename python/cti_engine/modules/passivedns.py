"""Passive DNS aggregation module for the first-party CTI engine."""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, AsyncIterator

from ..events import ScanEvent
from ..module_base import BaseModule
from ..targets import DOMAIN_RX


class PassiveDnsModule(BaseModule):
    slug = "passivedns"
    name = "Passive DNS"
    watched_types = {"domain", "ip"}
    produced_types = {"raw_dns_records", "ip", "internet_name", "co_hosted_site", "co_hosted_site_domain"}
    requires_key = False

    DEFAULT_BASE_URL = "https://api.passivedns.com"
    MNEMONIC_BASE_URL = "https://api.mnemonic.no/pdns/v3"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        timeout = int(ctx.request.settings.global_settings.get("http_timeout", 15) or 15)
        api_config = ctx.api_config_for(self.slug)
        api_key = str(api_config.get("api_key", "")).strip()
        base_url = str(api_config.get("base_url", "")).strip() or self.DEFAULT_BASE_URL
        records = self._collect_records(event, api_key, base_url, timeout, ctx)
        for child in self._events_from_records(records, event, ctx):
            yield child

    def _collect_records(
        self,
        event: ScanEvent,
        api_key: str,
        base_url: str,
        timeout: int,
        ctx,
    ) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        records.extend(self._collect_native_dns(event))
        records.extend(self._collect_mnemonic_pdns(event, timeout, ctx))
        if api_key:
            records.extend(self._collect_optional_api_pdns(event, api_key, base_url, timeout, ctx))

        unique: dict[tuple[str, str], dict[str, Any]] = {}
        for record in records:
            rrtype = str(record.get("rrtype", "") or "").strip().upper()
            rrvalue = str(record.get("rrvalue", "") or "").strip().lower()
            if not rrtype or not rrvalue:
                continue
            unique.setdefault((rrtype, rrvalue), record)
        return list(unique.values())

    def _collect_native_dns(self, event: ScanEvent) -> list[dict[str, Any]]:
        if event.event_type == "domain":
            results: list[dict[str, Any]] = []
            try:
                infos = socket.getaddrinfo(event.value, None, proto=socket.IPPROTO_TCP)
            except OSError:
                infos = []
            for info in infos:
                sockaddr = info[4]
                if isinstance(sockaddr, tuple) and sockaddr:
                    results.append({
                        "rrtype": "A",
                        "rrvalue": str(sockaddr[0]).strip(),
                        "source": "native_dns",
                    })
            return results

        try:
            hostname = socket.gethostbyaddr(event.value)[0]
        except OSError:
            return []
        return [{
            "rrtype": "PTR",
            "rrvalue": hostname.strip().lower().rstrip("."),
            "source": "native_dns",
        }]

    def _collect_mnemonic_pdns(self, event: ScanEvent, timeout: int, ctx) -> list[dict[str, Any]]:
        endpoint = f"{self.MNEMONIC_BASE_URL}/{urllib.parse.quote(event.value, safe='')}"
        request = urllib.request.Request(
            endpoint,
            headers={"Accept": "application/json", "User-Agent": "CTI Engine"},
            method="GET",
        )
        ctx.info(f"Fetching Mnemonic passive DNS data for {event.value}.", self.slug)

        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec - fixed provider URL
                status = int(getattr(response, "status", 200) or 200)
                content = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return []
            if exc.code == 429:
                ctx.error("Your request to Mnemonic passive DNS was throttled.", self.slug)
                return []
            ctx.warning(f"Mnemonic passive DNS request failed for {event.value}: HTTP {exc.code}", self.slug)
            return []
        except Exception as exc:
            ctx.warning(f"Mnemonic passive DNS request failed for {event.value}: {exc}", self.slug)
            return []

        if status != 200:
            ctx.warning(f"Mnemonic passive DNS returned HTTP {status} for {event.value}.", self.slug)
            return []

        try:
            decoded = json.loads(content)
        except json.JSONDecodeError as exc:
            ctx.error(f"Mnemonic passive DNS returned invalid JSON: {exc}", self.slug)
            return []

        rows = decoded.get("data") or []
        if not isinstance(rows, list):
            return []

        records: list[dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            rrvalue = str(row.get("answer", "") or "").strip()
            if not rrvalue:
                continue
            records.append({
                "rrtype": str(row.get("rrtype", "") or "A").strip().upper(),
                "rrvalue": rrvalue,
                "source": "mnemonic",
            })
        return records

    def _collect_optional_api_pdns(
        self,
        event: ScanEvent,
        api_key: str,
        base_url: str,
        timeout: int,
        ctx,
    ) -> list[dict[str, Any]]:
        endpoint = f"{base_url.rstrip('/')}/lookup/{urllib.parse.quote(event.value, safe='')}"
        request = urllib.request.Request(
            endpoint,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {api_key}",
                "User-Agent": "CTI Engine",
            },
            method="GET",
        )
        ctx.info(f"Fetching optional passive DNS provider data for {event.value}.", self.slug)

        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec - operator configured URL
                status = int(getattr(response, "status", 200) or 200)
                content = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                ctx.error("Passive DNS provider rejected the configured API key.", self.slug)
                return []
            if exc.code == 429:
                ctx.error("Your request to the passive DNS provider was throttled.", self.slug)
                return []
            ctx.warning(f"Passive DNS provider request failed for {event.value}: HTTP {exc.code}", self.slug)
            return []
        except Exception as exc:
            ctx.warning(f"Passive DNS provider request failed for {event.value}: {exc}", self.slug)
            return []

        if status != 200:
            ctx.warning(f"Passive DNS provider returned HTTP {status} for {event.value}.", self.slug)
            return []

        try:
            decoded = json.loads(content)
        except json.JSONDecodeError as exc:
            ctx.error(f"Passive DNS provider returned invalid JSON: {exc}", self.slug)
            return []

        rows = decoded.get("records") or decoded.get("data") or []
        if not isinstance(rows, list):
            return []

        records: list[dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            rrvalue = str(row.get("rdata", row.get("value", "")) or "").strip()
            if not rrvalue:
                continue
            records.append({
                "rrtype": str(row.get("rrtype", row.get("type", "A")) or "A").strip().upper(),
                "rrvalue": rrvalue,
                "source": "provider_api",
            })
        return records

    def _events_from_records(
        self,
        records: list[dict[str, Any]],
        parent_event: ScanEvent,
        ctx,
    ) -> list[ScanEvent]:
        events: list[ScanEvent] = []
        for record in records[:40]:
            rrtype = str(record.get("rrtype", "") or "").strip().upper()
            rrvalue = str(record.get("rrvalue", "") or "").strip().rstrip(".")
            if not rrtype or not rrvalue:
                continue
            events.append(ScanEvent(
                event_type="raw_dns_records",
                value=f"{rrtype} {rrvalue}",
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=75,
                visibility=100,
                risk_score=0,
                tags=["passivedns", record.get("source", "record"), rrtype.lower()],
                raw_payload={"query": parent_event.value},
            ))

            child_type = self._event_type_for_value(rrvalue, parent_event.event_type)
            if child_type is None:
                continue

            events.append(ScanEvent(
                event_type=child_type,
                value=rrvalue.lower() if child_type != "ip" else rrvalue,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=78,
                visibility=100,
                risk_score=5,
                tags=["passivedns", record.get("source", "record")],
                raw_payload={"rrtype": rrtype, "query": parent_event.value},
            ))

            if child_type == "co_hosted_site" and DOMAIN_RX.match(rrvalue.lower()):
                events.append(ScanEvent(
                    event_type="co_hosted_site_domain",
                    value=rrvalue.lower(),
                    source_module=self.slug,
                    root_target=ctx.root_target,
                    parent_event_id=parent_event.event_id,
                    confidence=78,
                    visibility=100,
                    risk_score=5,
                    tags=["passivedns", record.get("source", "record"), "domain"],
                    raw_payload={"rrtype": rrtype, "query": parent_event.value},
                ))
        return events

    def _event_type_for_value(self, value: str, parent_type: str) -> str | None:
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
            return "co_hosted_site" if parent_type == "ip" else "internet_name"
        return None
