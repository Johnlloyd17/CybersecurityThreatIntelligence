"""SecurityTrails module for the first-party CTI engine."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, AsyncIterator

from ..events import ScanEvent
from ..module_base import BaseModule
from ..targets import DOMAIN_RX


class SecurityTrailsModule(BaseModule):
    slug = "securitytrails"
    name = "SecurityTrails"
    watched_types = {"domain", "ip", "email"}
    produced_types = {
        "internet_name",
        "affiliate_internet_name",
        "affiliate_domain_name",
        "co_hosted_site",
        "provider_hosting",
    }
    requires_key = True

    DEFAULT_BASE_URL = "https://api.securitytrails.com/v1"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        api_config = ctx.api_config_for(self.slug)
        api_key = str(api_config.get("api_key", "")).strip()
        if not api_key:
            ctx.error("SecurityTrails module requires an API key.", self.slug)
            return

        base_url = str(api_config.get("base_url", "")).strip() or self.DEFAULT_BASE_URL
        timeout = int(ctx.request.settings.global_settings.get("http_timeout", 15) or 15)

        if event.event_type == "domain":
            payload = self._fetch_domain_subdomains(base_url, event.value, api_key, timeout, ctx)
            if payload is None:
                return
            for child in self._events_from_domain_payload(payload, event, ctx):
                yield child
            return

        if event.event_type == "ip":
            payload = self._fetch_search_records(base_url, "ipv4", event.value, api_key, timeout, ctx)
            if payload is None:
                return
            for child in self._events_from_ip_payload(payload, event, ctx):
                yield child
            return

        if event.event_type == "email":
            payload = self._fetch_search_records(base_url, "whois_email", event.value, api_key, timeout, ctx)
            if payload is None:
                return
            for child in self._events_from_email_payload(payload, event, ctx):
                yield child
            return

        ctx.debug(f"SecurityTrails does not yet handle event type '{event.event_type}'.", self.slug)

    def _fetch_domain_subdomains(
        self,
        base_url: str,
        domain: str,
        api_key: str,
        timeout: int,
        ctx,
    ) -> list[str] | None:
        endpoint = f"{base_url.rstrip('/')}/domain/{urllib.parse.quote(domain, safe='')}/subdomains"
        request = urllib.request.Request(
            endpoint,
            headers={"Accept": "application/json", "User-Agent": "CTI Engine", "APIKEY": api_key},
            method="GET",
        )
        ctx.info(f"Fetching SecurityTrails subdomains for {domain}.", self.slug)
        payload = self._request_json(request, timeout, ctx, domain)
        if not isinstance(payload, dict):
            return None
        rows = payload.get("subdomains") or []
        if not isinstance(rows, list):
            return None
        return [str(item).strip().lower() for item in rows if str(item).strip()]

    def _fetch_search_records(
        self,
        base_url: str,
        field: str,
        value: str,
        api_key: str,
        timeout: int,
        ctx,
    ) -> list[dict[str, Any]] | None:
        endpoint = f"{base_url.rstrip('/')}/search/list/?page=1"
        request = urllib.request.Request(
            endpoint,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "CTI Engine",
                "APIKEY": api_key,
            },
            data=json.dumps({"filter": {field: value}}).encode("utf-8"),
            method="POST",
        )
        ctx.info(f"Fetching SecurityTrails search data for {value}.", self.slug)
        payload = self._request_json(request, timeout, ctx, value)
        if not isinstance(payload, dict):
            return None
        rows = payload.get("records") or []
        if not isinstance(rows, list):
            return None
        return [row for row in rows if isinstance(row, dict)]

    def _request_json(self, request: urllib.request.Request, timeout: int, ctx, value: str) -> dict[str, Any] | None:
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec - fixed provider URL
                status = int(getattr(response, "status", 200) or 200)
                content = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                ctx.info(f"SecurityTrails has no data for {value}.", self.slug)
                return None
            if exc.code == 429:
                ctx.error("Your request to SecurityTrails was throttled.", self.slug)
                return None
            if exc.code in (401, 403):
                ctx.error("SecurityTrails rejected the API key or access token.", self.slug)
                return None
            ctx.warning(f"SecurityTrails request failed for {value}: HTTP {exc.code}", self.slug)
            return None
        except Exception as exc:
            ctx.warning(f"SecurityTrails request failed for {value}: {exc}", self.slug)
            return None

        if status >= 400:
            ctx.warning(f"SecurityTrails returned HTTP {status} for {value}.", self.slug)
            return None

        try:
            return json.loads(content)
        except json.JSONDecodeError as exc:
            ctx.error(f"SecurityTrails returned invalid JSON: {exc}", self.slug)
            return None

    def _events_from_domain_payload(
        self,
        payload: list[str],
        parent_event: ScanEvent,
        ctx,
    ) -> list[ScanEvent]:
        events: list[ScanEvent] = []
        seen: set[str] = set()
        for subdomain in payload:
            fqdn = f"{subdomain}.{parent_event.value}".lower()
            if fqdn in seen:
                continue
            seen.add(fqdn)
            events.append(ScanEvent(
                event_type="internet_name",
                value=fqdn,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=80,
                visibility=100,
                risk_score=10,
                tags=["securitytrails", "subdomain"],
                raw_payload={"parent_domain": parent_event.value},
            ))
        return events

    def _events_from_ip_payload(
        self,
        payload: list[dict[str, Any]],
        parent_event: ScanEvent,
        ctx,
    ) -> list[ScanEvent]:
        events: list[ScanEvent] = []
        seen_hosts: set[str] = set()
        seen_providers: set[str] = set()
        for row in payload:
            for provider in row.get("host_provider") or []:
                provider_name = str(provider).strip()
                if provider_name and provider_name not in seen_providers:
                    seen_providers.add(provider_name)
                    events.append(ScanEvent(
                        event_type="provider_hosting",
                        value=provider_name,
                        source_module=self.slug,
                        root_target=ctx.root_target,
                        parent_event_id=parent_event.event_id,
                        confidence=75,
                        visibility=100,
                        risk_score=0,
                        tags=["securitytrails", "hosting"],
                        raw_payload={"ip": parent_event.value},
                    ))

            hostname = str(row.get("hostname", "") or "").strip().lower()
            if hostname and hostname not in seen_hosts and hostname != parent_event.value:
                seen_hosts.add(hostname)
                events.append(ScanEvent(
                    event_type="co_hosted_site",
                    value=hostname,
                    source_module=self.slug,
                    root_target=ctx.root_target,
                    parent_event_id=parent_event.event_id,
                    confidence=78,
                    visibility=100,
                    risk_score=5,
                    tags=["securitytrails", "cohost"],
                    raw_payload={"ip": parent_event.value},
                ))
        return events

    def _events_from_email_payload(
        self,
        payload: list[dict[str, Any]],
        parent_event: ScanEvent,
        ctx,
    ) -> list[ScanEvent]:
        events: list[ScanEvent] = []
        seen: set[str] = set()
        for row in payload:
            hostname = str(row.get("hostname", "") or "").strip().lower()
            if not hostname or hostname in seen:
                continue
            seen.add(hostname)
            events.append(ScanEvent(
                event_type="affiliate_internet_name",
                value=hostname,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=78,
                visibility=100,
                risk_score=8,
                tags=["securitytrails", "reverse_whois", "email"],
                raw_payload={"source_email": parent_event.value},
            ))
            if DOMAIN_RX.match(hostname):
                events.append(ScanEvent(
                    event_type="affiliate_domain_name",
                    value=hostname,
                    source_module=self.slug,
                    root_target=ctx.root_target,
                    parent_event_id=parent_event.event_id,
                    confidence=78,
                    visibility=100,
                    risk_score=8,
                    tags=["securitytrails", "reverse_whois", "email", "domain"],
                    raw_payload={"source_email": parent_event.value},
                ))
        return events
