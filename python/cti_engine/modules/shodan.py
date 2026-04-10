"""Shodan module for the first-party CTI engine."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, AsyncIterator

from ..events import ScanEvent
from ..module_base import BaseModule


class ShodanModule(BaseModule):
    slug = "shodan"
    name = "Shodan"
    watched_types = {"domain", "ip"}
    produced_types = {
        "ip",
        "internet_name",
        "open_port",
        "cve",
        "malicious_ip",
    }
    requires_key = True

    _RISKY_PORTS = {21, 22, 23, 445, 3389, 5900, 8080, 8443}

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        api_config = ctx.api_config_for(self.slug)
        api_key = str(api_config.get("api_key", "")).strip()
        if not api_key:
            ctx.error("Shodan module requires an API key.", self.slug)
            return

        base_url = str(api_config.get("base_url", "")).strip() or "https://api.shodan.io"
        timeout = int(ctx.request.settings.global_settings.get("http_timeout", 15) or 15)

        if event.event_type == "domain":
            child = self._resolve_domain_to_ip(base_url, event, api_key, timeout, ctx)
            if child is not None:
                yield child
            return

        if event.event_type == "ip":
            payload = self._fetch_host_payload(base_url, event.value, api_key, timeout, ctx)
            if payload is None:
                return

            for child in self._events_from_host_payload(payload, event, ctx):
                yield child
            return

        ctx.debug(f"Shodan module does not yet handle event type '{event.event_type}'.", self.slug)

    def _resolve_domain_to_ip(
        self,
        base_url: str,
        parent_event: ScanEvent,
        api_key: str,
        timeout: int,
        ctx,
    ) -> ScanEvent | None:
        encoded_domain = urllib.parse.quote(parent_event.value, safe="")
        endpoint = (
            f"{base_url.rstrip('/')}/dns/resolve"
            f"?hostnames={encoded_domain}&key={urllib.parse.quote(api_key, safe='')}"
        )
        payload = self._request_json(endpoint, timeout, ctx, parent_event.value)
        if payload is None:
            return None

        resolved_ip = str(payload.get(parent_event.value, "")).strip()
        if not resolved_ip:
            ctx.info(f"Shodan has no DNS resolution data for {parent_event.value}.", self.slug)
            return None

        ctx.info(f"Shodan resolved {parent_event.value} -> {resolved_ip}.", self.slug)
        return self._resolve_domain_to_ip_event(resolved_ip, parent_event, ctx)

    def _resolve_domain_to_ip_event(self, resolved_ip: str, parent_event: ScanEvent, ctx) -> ScanEvent:
        return ScanEvent(
            event_type="ip",
            value=resolved_ip,
            source_module=self.slug,
            root_target=ctx.root_target,
            parent_event_id=parent_event.event_id,
            confidence=95,
            visibility=100,
            risk_score=0,
            tags=["shodan", "resolved"],
            raw_payload={"domain": parent_event.value},
        )

    def _fetch_host_payload(
        self,
        base_url: str,
        ip: str,
        api_key: str,
        timeout: int,
        ctx,
    ) -> dict[str, Any] | None:
        endpoint = (
            f"{base_url.rstrip('/')}/shodan/host/"
            f"{urllib.parse.quote(ip, safe='')}"
            f"?key={urllib.parse.quote(api_key, safe='')}"
        )
        payload = self._request_json(endpoint, timeout, ctx, ip)
        if payload is None:
            return None

        if not isinstance(payload, dict) or not payload:
            ctx.info(f"Shodan returned no host data for {ip}.", self.slug)
            return None

        return payload

    def _request_json(self, endpoint: str, timeout: int, ctx, value: str) -> dict[str, Any] | None:
        ctx.info(f"Fetching Shodan data for {value}.", self.slug)
        request = urllib.request.Request(
            endpoint,
            headers={"User-Agent": "CTI Engine", "Accept": "application/json"},
            method="GET",
        )

        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec - fixed provider URL
                status = int(getattr(response, "status", 200) or 200)
                content = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                ctx.info(f"Shodan has no data for {value}.", self.slug)
                return None
            if exc.code == 429:
                ctx.error("Your request to Shodan was throttled.", self.slug)
                return None
            if exc.code in (401, 403):
                ctx.error("Shodan rejected the API key or access token.", self.slug)
                return None
            ctx.warning(f"Shodan request failed for {value}: HTTP {exc.code}", self.slug)
            return None
        except Exception as exc:
            ctx.warning(f"Shodan request failed for {value}: {exc}", self.slug)
            return None

        if status >= 400:
            ctx.warning(f"Shodan returned HTTP {status} for {value}.", self.slug)
            return None

        try:
            return json.loads(content)
        except json.JSONDecodeError as exc:
            ctx.error(f"Shodan returned invalid JSON: {exc}", self.slug)
            return None

    def _events_from_host_payload(
        self,
        payload: dict[str, Any],
        parent_event: ScanEvent,
        ctx,
    ) -> list[ScanEvent]:
        events: list[ScanEvent] = []

        ports = self._normalize_int_list(payload.get("ports") or [])
        vulns = self._extract_vulns(payload.get("vulns") or {})
        hostnames = self._normalize_string_list(payload.get("hostnames") or [])
        domains = self._normalize_string_list(payload.get("domains") or [])

        risky_ports = [port for port in ports if port in self._RISKY_PORTS]
        if vulns or risky_ports:
            events.append(ScanEvent(
                event_type="malicious_ip",
                value=parent_event.value,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=min(99, 60 + (len(vulns) * 8) + (len(risky_ports) * 4)),
                visibility=100,
                risk_score=self._host_risk_score(len(vulns), len(risky_ports), len(ports)),
                tags=["shodan", "host", "risky"],
                raw_payload={
                    "vulnerability_count": len(vulns),
                    "risky_port_count": len(risky_ports),
                    "open_port_count": len(ports),
                },
            ))

        for name in hostnames + domains:
            if name.strip().lower() == parent_event.value.strip().lower():
                continue
            events.append(ScanEvent(
                event_type="internet_name",
                value=name,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=80,
                visibility=100,
                risk_score=10,
                tags=["shodan", "hostname"],
                raw_payload={"parent_ip": parent_event.value},
            ))

        for port in ports:
            is_risky = port in self._RISKY_PORTS
            events.append(ScanEvent(
                event_type="open_port",
                value=f"{parent_event.value}:{port}",
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=90,
                visibility=100,
                risk_score=25 if is_risky else 5,
                tags=["shodan", "port", f"port-{port}"] + (["risky-port"] if is_risky else []),
                raw_payload={"ip": parent_event.value, "port": port},
            ))

        for vuln in vulns:
            events.append(ScanEvent(
                event_type="cve",
                value=vuln,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=90,
                visibility=100,
                risk_score=70,
                tags=["shodan", "cve"],
                raw_payload={"ip": parent_event.value},
            ))

        return events

    def _normalize_int_list(self, values: list[Any]) -> list[int]:
        normalized: list[int] = []
        seen: set[int] = set()
        for value in values:
            try:
                port = int(value)
            except (TypeError, ValueError):
                continue
            if port <= 0 or port in seen:
                continue
            seen.add(port)
            normalized.append(port)
        normalized.sort()
        return normalized

    def _normalize_string_list(self, values: list[Any]) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()
        for value in values:
            item = str(value or "").strip().lower()
            if not item or item in seen:
                continue
            seen.add(item)
            normalized.append(item)
        return normalized

    def _extract_vulns(self, payload: Any) -> list[str]:
        values: list[str] = []
        if isinstance(payload, dict):
            source = payload.keys()
        elif isinstance(payload, list):
            source = payload
        else:
            source = []

        seen: set[str] = set()
        for value in source:
            vuln = str(value or "").strip().upper()
            if not vuln or vuln in seen:
                continue
            seen.add(vuln)
            values.append(vuln)
        values.sort()
        return values

    def _host_risk_score(self, vuln_count: int, risky_port_count: int, open_port_count: int) -> int:
        vuln_score = min(70, vuln_count * 15)
        risky_score = min(20, risky_port_count * 6)
        exposure_score = min(10, max(0, open_port_count - 5))
        return max(0, min(100, vuln_score + risky_score + exposure_score))
