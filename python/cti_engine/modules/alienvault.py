"""AlienVault OTX module for the first-party CTI engine."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, AsyncIterator

from ..events import ScanEvent
from ..module_base import BaseModule


class AlienVaultModule(BaseModule):
    slug = "alienvault"
    name = "AlienVault OTX"
    watched_types = {"domain", "ip", "url", "hash"}
    produced_types = {
        "internet_name",
        "linked_url_internal",
        "ip",
        "ipv6",
        "email",
        "hash",
        "cve",
        "malicious_domain",
        "malicious_ip",
        "malicious_url",
        "malicious_hash",
    }
    requires_key = True

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        if event.event_type == "domain":
            for child in self._events_for_domain(event, ctx):
                yield child
            return

        payload = self._fetch_payload(event.event_type, event.value, ctx)
        if payload is None:
            return

        for child in self._events_from_payload(payload, event, ctx):
            yield child

    def _events_for_domain(self, event: ScanEvent, ctx) -> list[ScanEvent]:
        events: list[ScanEvent] = []

        payload = self._fetch_payload(event.event_type, event.value, ctx)
        if payload is not None:
            events.extend(self._events_from_payload(payload, event, ctx))

        url_entries = self._fetch_url_list_entries(event.value, "hostname", ctx)
        url_entries.extend(self._fetch_url_list_entries(event.value, "domain", ctx))
        events.extend(self._events_from_url_entries(url_entries, event, ctx))

        return events

    def _fetch_payload(
        self,
        event_type: str,
        value: str,
        ctx,
    ) -> dict[str, Any] | None:
        api_config = ctx.api_config_for(self.slug)
        base_url = str(api_config.get("base_url", "")).strip() or "https://otx.alienvault.com/api/v1"
        api_key = str(api_config.get("api_key", "")).strip()
        if not api_key:
            ctx.error("AlienVault OTX module requires an API key.", self.slug)
            return None
        timeout = int(ctx.request.settings.global_settings.get("http_timeout", 15) or 15)

        endpoint = self._build_endpoint(base_url, event_type, value)
        if endpoint is None:
            ctx.debug(f"AlienVault module does not yet handle event type '{event_type}'.", self.slug)
            return None

        return self._fetch_json(endpoint, api_key, timeout, value, ctx)

    def _fetch_url_list_entries(self, value: str, indicator_kind: str, ctx) -> list[dict[str, Any]]:
        api_config = ctx.api_config_for(self.slug)
        base_url = str(api_config.get("base_url", "")).strip() or "https://otx.alienvault.com/api/v1"
        api_key = str(api_config.get("api_key", "")).strip()
        if not api_key:
            ctx.error("AlienVault OTX module requires an API key.", self.slug)
            return []
        timeout = int(ctx.request.settings.global_settings.get("http_timeout", 15) or 15)
        module_settings = ctx.module_settings_for(self.slug)
        max_pages = max(1, int(module_settings.get("max_pages", 50) or 50))
        limit = max(1, int(module_settings.get("page_limit", 50) or 50))

        results: list[dict[str, Any]] = []
        for page in range(1, max_pages + 1):
            params = urllib.parse.urlencode({
                "page": page,
                "limit": limit,
            })
            endpoint = (
                f"{base_url.rstrip('/')}/indicators/{indicator_kind}/"
                f"{urllib.parse.quote(value, safe='')}/url_list?{params}"
            )
            payload = self._fetch_json(endpoint, api_key, timeout, value, ctx, quiet_not_found=True)
            if payload is None:
                break

            url_list = payload.get("url_list")
            if not isinstance(url_list, list) or not url_list:
                break

            results.extend(item for item in url_list if isinstance(item, dict))
            if not payload.get("has_next"):
                break

        return results

    def _fetch_json(
        self,
        endpoint: str,
        api_key: str,
        timeout: int,
        value: str,
        ctx,
        quiet_not_found: bool = False,
    ) -> dict[str, Any] | None:
        headers = {"User-Agent": "CTI Engine", "Accept": "application/json"}
        if api_key:
            headers["X-OTX-API-KEY"] = api_key

        ctx.info(f"Fetching AlienVault OTX data for {value}.", self.slug)
        request = urllib.request.Request(endpoint, headers=headers, method="GET")

        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec - fixed provider URL
                status = int(getattr(response, "status", 200) or 200)
                content = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                if not quiet_not_found:
                    ctx.info(f"AlienVault OTX has no data for {value}.", self.slug)
                return None
            if exc.code == 429:
                ctx.error("Your request to AlienVault OTX was throttled.", self.slug)
                return None
            if exc.code in (401, 403):
                ctx.error("AlienVault OTX rejected the API key or access token.", self.slug)
                return None
            ctx.warning(f"AlienVault OTX request failed for {value}: HTTP {exc.code}", self.slug)
            return None
        except Exception as exc:
            ctx.warning(f"AlienVault OTX request failed for {value}: {exc}", self.slug)
            return None

        if status >= 400:
            ctx.warning(f"AlienVault OTX returned HTTP {status} for {value}.", self.slug)
            return None

        try:
            return json.loads(content)
        except json.JSONDecodeError as exc:
            ctx.error(f"AlienVault OTX returned invalid JSON: {exc}", self.slug)
            return None

    def _build_endpoint(self, base_url: str, event_type: str, value: str) -> str | None:
        base = base_url.rstrip("/")
        encoded = urllib.parse.quote(value, safe="")
        if event_type == "domain":
            return f"{base}/indicators/domain/{encoded}/general"
        if event_type == "ip":
            return f"{base}/indicators/IPv4/{encoded}/general"
        if event_type == "url":
            return f"{base}/indicators/url/{encoded}/general"
        if event_type == "hash":
            return f"{base}/indicators/file/{encoded}/general"
        return None

    def _events_from_payload(
        self,
        payload: dict[str, Any],
        parent_event: ScanEvent,
        ctx,
    ) -> list[ScanEvent]:
        pulse_info = payload.get("pulse_info") or {}
        pulses = pulse_info.get("pulses") or []
        pulse_count = int(pulse_info.get("count", 0) or 0)

        events: list[ScanEvent] = []
        parent_malicious_type = self._malicious_type_for(parent_event.event_type)
        if pulse_count > 0 and parent_malicious_type is not None:
            events.append(ScanEvent(
                event_type=parent_malicious_type,
                value=parent_event.value,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=min(99, 55 + min(40, pulse_count * 5)),
                visibility=100,
                risk_score=self._risk_from_pulse_count(pulse_count),
                tags=["alienvault", "otx", "pulse"],
                raw_payload={"pulse_count": pulse_count},
            ))

        for pulse in pulses:
            for indicator in pulse.get("indicators") or []:
                child = self._event_from_indicator(indicator, parent_event, ctx)
                if child is not None:
                    events.append(child)

        return events

    def _events_from_url_entries(
        self,
        url_entries: list[dict[str, Any]],
        parent_event: ScanEvent,
        ctx,
    ) -> list[ScanEvent]:
        events: list[ScanEvent] = []
        seen_urls: set[str] = set()

        for entry in url_entries:
            url_value = str(entry.get("url", "")).strip()
            if not url_value or url_value in seen_urls:
                continue

            host = self._hostname_from_url(url_value)
            if not host or not self._host_matches_target(host, parent_event.value, ctx.root_target):
                continue

            seen_urls.add(url_value)
            events.append(ScanEvent(
                event_type="linked_url_internal",
                value=url_value,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=80,
                visibility=100,
                risk_score=25,
                tags=["alienvault", "otx", "url_list"],
                raw_payload=entry,
            ))

        return events

    def _event_from_indicator(
        self,
        indicator: dict[str, Any],
        parent_event: ScanEvent,
        ctx,
    ) -> ScanEvent | None:
        indicator_type = str(indicator.get("type", "")).strip()
        indicator_value = str(indicator.get("indicator", "")).strip()
        if not indicator_type or not indicator_value:
            return None

        event_type = self._map_indicator_type(indicator_type)
        if event_type is None:
            return None

        if indicator_value == parent_event.value and event_type == parent_event.event_type:
            return None

        risk_score = 25 if event_type == "linked_url_internal" else 15
        confidence = 80 if event_type == "linked_url_internal" else 70

        return ScanEvent(
            event_type=event_type,
            value=indicator_value,
            source_module=self.slug,
            root_target=ctx.root_target,
            parent_event_id=parent_event.event_id,
            confidence=confidence,
            visibility=100,
            risk_score=risk_score,
            tags=["alienvault", "otx", indicator_type.lower()],
            raw_payload=indicator,
        )

    def _map_indicator_type(self, indicator_type: str) -> str | None:
        normalized = indicator_type.strip().lower()
        if normalized in {"ipv4", "ipv4 - source"}:
            return "ip"
        if normalized == "ipv6":
            return "ipv6"
        if normalized in {"domain", "hostname"}:
            return "internet_name"
        if normalized in {"url", "uri"}:
            return "linked_url_internal"
        if normalized == "email":
            return "email"
        if normalized in {"filehash-sha256", "filehash-sha1", "filehash-md5"}:
            return "hash"
        if normalized == "cve":
            return "cve"
        return None

    def _risk_from_pulse_count(self, pulse_count: int) -> int:
        if pulse_count <= 0:
            return 0
        if pulse_count <= 2:
            return 15
        if pulse_count <= 5:
            return 35
        if pulse_count <= 10:
            return 55
        if pulse_count <= 20:
            return 75
        return min(100, 85 + int((pulse_count - 20) / 10))

    def _malicious_type_for(self, event_type: str) -> str | None:
        mapping = {
            "domain": "malicious_domain",
            "ip": "malicious_ip",
            "url": "malicious_url",
            "hash": "malicious_hash",
        }
        return mapping.get(event_type)

    def _hostname_from_url(self, value: str) -> str | None:
        try:
            parsed = urllib.parse.urlsplit(value)
        except ValueError:
            return None

        host = str(parsed.hostname or "").strip().lower().rstrip(".")
        return host or None

    def _host_matches_target(self, host: str, parent_value: str, root_target: str) -> bool:
        candidate = host.strip().lower().rstrip(".")
        primary = self._normalize_host_like(parent_value)
        root = self._normalize_host_like(root_target)

        return any(
            self._matches_host_scope(candidate, scope)
            for scope in (primary, root)
            if scope
        )

    def _normalize_host_like(self, value: str) -> str:
        normalized = value.strip().lower()
        if not normalized:
            return ""
        if "://" in normalized:
            return self._hostname_from_url(normalized) or ""
        return normalized.rstrip(".")

    def _matches_host_scope(self, host: str, scope: str) -> bool:
        if not host or not scope:
            return False
        return host == scope or host.endswith("." + scope) or scope.endswith("." + host)
