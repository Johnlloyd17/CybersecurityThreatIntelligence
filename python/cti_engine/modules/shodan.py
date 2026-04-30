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
        "open_port",
        "open_port_banner",
        "software_used",
        "bgp_as_member",
        "operating_system",
        "device_type",
        "physical_location",
        "raw_rir_data",
        "vulnerability_cve_critical",
        "vulnerability_cve_high",
        "vulnerability_cve_medium",
        "vulnerability_cve_low",
        "vulnerability_general",
    }
    requires_key = True

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

        events.append(ScanEvent(
            event_type="raw_rir_data",
            value=json.dumps(payload, separators=(",", ":"), sort_keys=True),
            source_module=self.slug,
            root_target=ctx.root_target,
            parent_event_id=parent_event.event_id,
            confidence=85,
            visibility=100,
            risk_score=0,
            tags=["shodan", "raw"],
            raw_payload={"ip": parent_event.value},
        ))

        operating_system = str(payload.get("os", "")).strip()
        if operating_system:
            events.append(ScanEvent(
                event_type="operating_system",
                value=f"{operating_system} ({parent_event.value})",
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=85,
                visibility=100,
                risk_score=0,
                tags=["shodan", "os"],
                raw_payload={"ip": parent_event.value},
            ))

        device_type = str(payload.get("devtype", "")).strip()
        if device_type:
            events.append(ScanEvent(
                event_type="device_type",
                value=f"{device_type} ({parent_event.value})",
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=85,
                visibility=100,
                risk_score=0,
                tags=["shodan", "device"],
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
                confidence=80,
                visibility=100,
                risk_score=0,
                tags=["shodan", "geo"],
                raw_payload={"ip": parent_event.value},
            ))

        data_rows = payload.get("data")
        if not isinstance(data_rows, list) or not data_rows:
            data_rows = [payload]

        seen_ports: set[str] = set()
        seen_banners: set[str] = set()
        seen_products: set[str] = set()
        seen_asns: set[str] = set()
        seen_vulns: set[str] = set()

        for row in data_rows:
            if not isinstance(row, dict):
                continue

            port = self._normalize_port(row.get("port"))
            if port is not None:
                port_value = f"{parent_event.value}:{port}"
                if port_value not in seen_ports:
                    seen_ports.add(port_value)
                    events.append(ScanEvent(
                        event_type="open_port",
                        value=port_value,
                        source_module=self.slug,
                        root_target=ctx.root_target,
                        parent_event_id=parent_event.event_id,
                        confidence=90,
                        visibility=100,
                        risk_score=5,
                        tags=["shodan", "port", f"port-{port}"],
                        raw_payload={"ip": parent_event.value, "port": port},
                    ))

            banner = str(row.get("banner", "")).strip()
            if banner and banner not in seen_banners:
                seen_banners.add(banner)
                events.append(ScanEvent(
                    event_type="open_port_banner",
                    value=banner,
                    source_module=self.slug,
                    root_target=ctx.root_target,
                    parent_event_id=parent_event.event_id,
                    confidence=80,
                    visibility=100,
                    risk_score=0,
                    tags=["shodan", "banner"],
                    raw_payload={"ip": parent_event.value, "port": port},
                ))

            product = str(row.get("product", "")).strip()
            if product and product not in seen_products:
                seen_products.add(product)
                events.append(ScanEvent(
                    event_type="software_used",
                    value=product,
                    source_module=self.slug,
                    root_target=ctx.root_target,
                    parent_event_id=parent_event.event_id,
                    confidence=80,
                    visibility=100,
                    risk_score=0,
                    tags=["shodan", "software"],
                    raw_payload={"ip": parent_event.value},
                ))

            asn = str(row.get("asn", "")).strip().upper()
            if asn.startswith("AS"):
                asn = asn[2:]
            if asn and asn not in seen_asns:
                seen_asns.add(asn)
                events.append(ScanEvent(
                    event_type="bgp_as_member",
                    value=asn,
                    source_module=self.slug,
                    root_target=ctx.root_target,
                    parent_event_id=parent_event.event_id,
                    confidence=80,
                    visibility=100,
                    risk_score=0,
                    tags=["shodan", "asn"],
                    raw_payload={"ip": parent_event.value},
                ))

            for vuln_name, vuln_payload in self._extract_vuln_entries(row.get("vulns")):
                normalized = vuln_name.strip().upper()
                if not normalized or normalized in seen_vulns:
                    continue
                seen_vulns.add(normalized)
                events.append(ScanEvent(
                    event_type=self._vuln_event_type(normalized, vuln_payload),
                    value=normalized,
                    source_module=self.slug,
                    root_target=ctx.root_target,
                    parent_event_id=parent_event.event_id,
                    confidence=90,
                    visibility=100,
                    risk_score=70,
                    tags=["shodan", "cve"],
                    raw_payload={"ip": parent_event.value, "details": vuln_payload},
                ))

        return events

    def _normalize_port(self, value: Any) -> int | None:
        try:
            port = int(value)
        except (TypeError, ValueError):
            return None
        if port <= 0:
            return None
        return port

    def _format_location(self, payload: dict[str, Any]) -> str:
        city = str(payload.get("city", "")).strip()
        country = str(payload.get("country_name", "")).strip()
        parts = [part for part in [city, country] if part]
        return ", ".join(parts)

    def _extract_vuln_entries(self, payload: Any) -> list[tuple[str, Any]]:
        entries: list[tuple[str, Any]] = []
        if isinstance(payload, dict):
            for name, details in payload.items():
                entries.append((str(name or ""), details))
            return entries
        if isinstance(payload, list):
            for item in payload:
                entries.append((str(item or ""), None))
        return entries

    def _vuln_event_type(self, vuln_name: str, details: Any) -> str:
        cvss = None
        if isinstance(details, dict):
            raw_cvss = details.get("cvss")
            try:
                cvss = float(raw_cvss)
            except (TypeError, ValueError):
                cvss = None

        if not vuln_name.startswith("CVE-"):
            return "vulnerability_general"
        if cvss is None:
            return "vulnerability_general"
        if cvss >= 9.0:
            return "vulnerability_cve_critical"
        if cvss >= 7.0:
            return "vulnerability_cve_high"
        if cvss >= 4.0:
            return "vulnerability_cve_medium"
        return "vulnerability_cve_low"
