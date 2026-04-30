"""LeakIX module aligned to SpiderFoot's host/domain leak behavior."""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, AsyncIterator

from ..events import ScanEvent
from ..module_base import BaseModule
from ..targets import EMAIL_RX


class LeakIxModule(BaseModule):
    slug = "leakix"
    name = "LeakIX"
    watched_types = {"domain", "ip", "email"}
    produced_types = {
        "raw_rir_data",
        "physical_location",
        "open_tcp_port",
        "operating_system",
        "software_used",
        "webserver_banner",
        "leaksite_content",
        "internet_name",
        "internet_name_unresolved",
        "ip",
        "breached_email_address",
    }
    requires_key = False

    DEFAULT_BASE_URL = "https://leakix.net"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        api_config = ctx.api_config_for(self.slug)
        api_key = str(api_config.get("api_key", "")).strip()
        base_url = str(api_config.get("base_url", "")).strip() or self.DEFAULT_BASE_URL
        timeout = int(ctx.request.settings.global_settings.get("http_timeout", 20) or 20)

        if event.event_type == "ip":
            payload = self._request_json(
                f"{base_url.rstrip('/')}/host/{urllib.parse.quote(event.value, safe='')}",
                api_key,
                timeout,
                ctx,
                event.value,
            )
            if not isinstance(payload, dict):
                return
            for child in self._events_from_host_payload(payload, event, ctx):
                yield child
            return

        if event.event_type == "domain":
            payload = self._request_json(
                f"{base_url.rstrip('/')}/domain/{urllib.parse.quote(event.value, safe='')}",
                api_key,
                timeout,
                ctx,
                event.value,
            )
            if not isinstance(payload, dict):
                return
            for child in self._events_from_host_payload(payload, event, ctx):
                yield child
            return

        if event.event_type == "email":
            payload = self._request_json(
                f"{base_url.rstrip('/')}/search?{urllib.parse.urlencode({'scope': 'leak', 'page': 0, 'q': event.value})}",
                api_key,
                timeout,
                ctx,
                event.value,
            )
            if not isinstance(payload, list):
                return
            for child in self._events_from_email_payload(
                [row for row in payload if isinstance(row, dict)],
                event,
                ctx,
            ):
                yield child
            return

        ctx.debug(f"LeakIX does not handle event type '{event.event_type}'.", self.slug)

    def _request_json(
        self,
        endpoint: str,
        api_key: str,
        timeout: int,
        ctx,
        value: str,
    ) -> dict[str, Any] | list[dict[str, Any]] | None:
        headers = {
            "Accept": "application/json",
            "User-Agent": "CTI Engine",
        }
        if api_key:
            headers["api-key"] = api_key
        request = urllib.request.Request(endpoint, headers=headers, method="GET")

        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec - fixed provider URL
                status = int(getattr(response, "status", 200) or 200)
                content = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                ctx.info(f"LeakIX has no data for {value}.", self.slug)
                return None
            if exc.code == 429:
                ctx.error("Your request to LeakIX was throttled.", self.slug)
                return None
            if exc.code in (401, 403):
                ctx.error("LeakIX rejected the API key.", self.slug)
                return None
            ctx.warning(f"LeakIX request failed for {value}: HTTP {exc.code}", self.slug)
            return None
        except Exception as exc:
            ctx.warning(f"LeakIX request failed for {value}: {exc}", self.slug)
            return None

        if status != 200:
            ctx.warning(f"LeakIX returned HTTP {status} for {value}.", self.slug)
            return None

        try:
            decoded = json.loads(content)
        except json.JSONDecodeError as exc:
            ctx.error(f"LeakIX returned invalid JSON: {exc}", self.slug)
            return None

        if isinstance(decoded, (dict, list)):
            return decoded
        return None

    def _events_from_host_payload(
        self,
        payload: dict[str, Any],
        parent_event: ScanEvent,
        ctx,
    ) -> list[ScanEvent]:
        verify_hostnames = self._truthy(ctx.module_settings_for(self.slug).get("verify", True))
        events: list[ScanEvent] = [
            ScanEvent(
                event_type="raw_rir_data",
                value=json.dumps(payload, ensure_ascii=False, sort_keys=True),
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=80,
                visibility=100,
                risk_score=0,
                tags=["leakix", "raw"],
                raw_payload={"query": parent_event.value},
            )
        ]

        services = payload.get("Services") if isinstance(payload.get("Services"), list) else []
        seen_hosts: set[str] = set()
        seen_ips: set[str] = set()
        seen_ports: set[str] = set()
        seen_banners: set[str] = set()
        seen_software: set[str] = set()
        seen_os: set[str] = set()

        for service in services:
            if not isinstance(service, dict):
                continue

            host_parent = parent_event
            ip_parent = parent_event

            hostname = str(service.get("host", "") or "").strip().lower().rstrip(".")
            if (
                hostname
                and parent_event.event_type == "domain"
                and self._matches_target(hostname, ctx.root_target)
                and hostname not in seen_hosts
            ):
                seen_hosts.add(hostname)
                event_type = "internet_name"
                if verify_hostnames and not self._resolves(hostname):
                    event_type = "internet_name_unresolved"

                host_parent = ScanEvent(
                    event_type=event_type,
                    value=hostname,
                    source_module=self.slug,
                    root_target=ctx.root_target,
                    parent_event_id=parent_event.event_id,
                    confidence=78,
                    visibility=100,
                    risk_score=5,
                    tags=["leakix", "host"],
                    raw_payload={"query": parent_event.value},
                )
                events.append(host_parent)

            ip_value = str(service.get("ip", "") or "").strip()
            if ip_value and parent_event.event_type != "ip" and ip_value not in seen_ips:
                seen_ips.add(ip_value)
                ip_parent = ScanEvent(
                    event_type="ip",
                    value=ip_value,
                    source_module=self.slug,
                    root_target=ctx.root_target,
                    parent_event_id=host_parent.event_id,
                    confidence=80,
                    visibility=100,
                    risk_score=0,
                    tags=["leakix", "ip"],
                    raw_payload={"query": parent_event.value},
                )
                events.append(ip_parent)

            port_value = str(service.get("port", "") or "").strip()
            if ip_value and port_value:
                port_key = f"{ip_value}:{port_value}"
                if port_key not in seen_ports:
                    seen_ports.add(port_key)
                    events.append(ScanEvent(
                        event_type="open_tcp_port",
                        value=port_key,
                        source_module=self.slug,
                        root_target=ctx.root_target,
                        parent_event_id=ip_parent.event_id,
                        confidence=76,
                        visibility=100,
                        risk_score=0,
                        tags=["leakix", "port"],
                        raw_payload={"query": parent_event.value},
                    ))

            headers = service.get("headers") if isinstance(service.get("headers"), dict) else {}
            servers = headers.get("Server") if isinstance(headers.get("Server"), list) else []
            for server in servers:
                banner = str(server or "").strip()
                if not banner or banner in seen_banners:
                    continue
                seen_banners.add(banner)
                events.append(ScanEvent(
                    event_type="webserver_banner",
                    value=banner,
                    source_module=self.slug,
                    root_target=ctx.root_target,
                    parent_event_id=host_parent.event_id,
                    confidence=74,
                    visibility=100,
                    risk_score=0,
                    tags=["leakix", "banner"],
                    raw_payload={"query": parent_event.value},
                ))

            geoip = service.get("geoip") if isinstance(service.get("geoip"), dict) else {}
            location = ", ".join(
                part
                for part in [
                    str(geoip.get("city_name", "") or "").strip(),
                    str(geoip.get("region_name", "") or "").strip(),
                    str(geoip.get("country_name", "") or "").strip(),
                ]
                if part
            )
            if location and ip_value:
                events.append(ScanEvent(
                    event_type="physical_location",
                    value=location,
                    source_module=self.slug,
                    root_target=ctx.root_target,
                    parent_event_id=ip_parent.event_id,
                    confidence=74,
                    visibility=100,
                    risk_score=0,
                    tags=["leakix", "geo"],
                    raw_payload={"query": parent_event.value},
                ))

            software = service.get("software") if isinstance(service.get("software"), dict) else {}
            software_value = " ".join(
                part for part in [
                    str(software.get("name", "") or "").strip(),
                    str(software.get("version", "") or "").strip(),
                ] if part
            )
            if software_value and software_value not in seen_software:
                seen_software.add(software_value)
                events.append(ScanEvent(
                    event_type="software_used",
                    value=software_value,
                    source_module=self.slug,
                    root_target=ctx.root_target,
                    parent_event_id=host_parent.event_id,
                    confidence=72,
                    visibility=100,
                    risk_score=0,
                    tags=["leakix", "software"],
                    raw_payload={"query": parent_event.value},
                ))

            os_value = str(software.get("os", "") or "").strip()
            if os_value and os_value not in seen_os:
                seen_os.add(os_value)
                events.append(ScanEvent(
                    event_type="operating_system",
                    value=os_value,
                    source_module=self.slug,
                    root_target=ctx.root_target,
                    parent_event_id=host_parent.event_id,
                    confidence=72,
                    visibility=100,
                    risk_score=0,
                    tags=["leakix", "os"],
                    raw_payload={"query": parent_event.value},
                ))

        leaks = payload.get("Leaks") if isinstance(payload.get("Leaks"), list) else []
        for leak in leaks:
            if not isinstance(leak, dict):
                continue
            protocol = str(leak.get("type", "") or "").strip().lower()
            hostname = str(leak.get("host", "") or "").strip().lower()
            if (
                protocol == "web"
                and hostname
                and "." in hostname
                and not hostname.replace(".", "").isdigit()
                and not self._matches_target(hostname, ctx.root_target)
            ):
                continue

            leak_data = str(leak.get("data", "") or "").strip()
            if not leak_data:
                continue
            events.append(ScanEvent(
                event_type="leaksite_content",
                value=leak_data,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=82,
                visibility=100,
                risk_score=60,
                tags=["leakix", "leak"],
                raw_payload={"query": parent_event.value},
            ))

        return events

    def _events_from_email_payload(
        self,
        payload: list[dict[str, Any]],
        parent_event: ScanEvent,
        ctx,
    ) -> list[ScanEvent]:
        if not payload:
            return []

        events: list[ScanEvent] = [
            ScanEvent(
                event_type="raw_rir_data",
                value=json.dumps(payload, ensure_ascii=False, sort_keys=True),
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=80,
                visibility=100,
                risk_score=0,
                tags=["leakix", "raw"],
                raw_payload={"query": parent_event.value},
            ),
            ScanEvent(
                event_type="breached_email_address",
                value=parent_event.value,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=min(95, 70 + len(payload) * 3),
                visibility=100,
                risk_score=min(85, 30 + len(payload) * 8),
                tags=["leakix", "email", "leak"],
                raw_payload={"match_count": len(payload)},
            ),
        ]

        seen_hosts: set[str] = set()
        for row in payload:
            host = str(row.get("host", "") or row.get("domain", "") or "").strip().lower().rstrip(".")
            if not host or host in seen_hosts or EMAIL_RX.match(host):
                continue
            seen_hosts.add(host)
            events.append(ScanEvent(
                event_type="internet_name",
                value=host,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=75,
                visibility=100,
                risk_score=5,
                tags=["leakix", "search"],
                raw_payload={"query": parent_event.value},
            ))

        return events

    def _matches_target(self, host: str, root_target: str) -> bool:
        candidate = str(host or "").strip().lower().rstrip(".")
        root = str(root_target or "").strip().lower().rstrip(".")
        if not candidate or not root:
            return False
        if candidate == root:
            return True
        return candidate.endswith("." + root)

    def _resolves(self, hostname: str) -> bool:
        try:
            return bool(socket.getaddrinfo(hostname, None))
        except OSError:
            return False

    def _truthy(self, value: Any) -> bool:
        return str(value).strip().lower() not in {"0", "false", "no", "off", ""}
