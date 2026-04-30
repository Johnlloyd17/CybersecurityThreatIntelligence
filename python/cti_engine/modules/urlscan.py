"""urlscan.io module for the first-party CTI engine.

The parity-safe path mirrors SpiderFoot's cached search behavior most closely
for domain targets. URL targets remain implemented, but are not promoted to the
parity-verified route yet.
"""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, AsyncIterator

from ..events import ScanEvent
from ..module_base import BaseModule


class UrlscanModule(BaseModule):
    slug = "urlscan"
    name = "urlscan.io"
    watched_types = {"domain", "url"}
    produced_types = {
        "raw_rir_data",
        "linked_url_internal",
        "internet_name",
        "internet_name_unresolved",
        "domain_name",
        "bgp_as_member",
        "webserver_banner",
        "physical_location",
    }
    requires_key = False

    DEFAULT_BASE_URL = "https://urlscan.io/api/v1"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        api_config = ctx.api_config_for(self.slug)
        api_key = str(api_config.get("api_key", "")).strip()

        settings = ctx.module_settings_for(self.slug)
        timeout = int(
            settings.get("timeout_seconds")
            or ctx.request.settings.global_settings.get("http_timeout", 15)
            or 15
        )
        result_limit = max(1, min(50, int(settings.get("result_limit", 20) or 20)))
        base_url = str(api_config.get("base_url", "")).strip() or self.DEFAULT_BASE_URL

        payload = self._fetch_payload(
            event_type=event.event_type,
            value=event.value,
            api_key=api_key,
            base_url=base_url,
            result_limit=result_limit,
            timeout=timeout,
            ctx=ctx,
        )
        if payload is None:
            return

        for child in self._events_from_payload(payload, event, ctx):
            yield child

    def _fetch_payload(
        self,
        *,
        event_type: str,
        value: str,
        api_key: str,
        base_url: str,
        result_limit: int,
        timeout: int,
        ctx,
    ) -> dict[str, Any] | None:
        search_query = self._build_search_query(event_type, value)
        if search_query is None:
            ctx.debug(f"urlscan.io does not yet handle event type '{event_type}'.", self.slug)
            return None

        query = urllib.parse.urlencode({"q": search_query, "size": result_limit})
        endpoint = f"{base_url.rstrip('/')}/search/?{query}"
        headers = {
            "Accept": "application/json",
            "User-Agent": "CTI Engine",
        }
        if api_key:
            headers["API-Key"] = api_key

        ctx.info(f"Fetching urlscan.io data for {value}.", self.slug)
        request = urllib.request.Request(endpoint, headers=headers, method="GET")

        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec - fixed provider URL
                status = int(getattr(response, "status", 200) or 200)
                content = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                ctx.info(f"urlscan.io has no data for {value}.", self.slug)
                return None
            if exc.code == 429:
                ctx.error("Your request to urlscan.io was throttled.", self.slug)
                return None
            if exc.code in (401, 403):
                ctx.error("urlscan.io rejected the API key or access token.", self.slug)
                return None
            ctx.warning(f"urlscan.io request failed for {value}: HTTP {exc.code}", self.slug)
            return None
        except Exception as exc:
            ctx.warning(f"urlscan.io request failed for {value}: {exc}", self.slug)
            return None

        if status >= 400:
            ctx.warning(f"urlscan.io returned HTTP {status} for {value}.", self.slug)
            return None

        try:
            decoded = json.loads(content)
        except json.JSONDecodeError as exc:
            ctx.error(f"urlscan.io returned invalid JSON: {exc}", self.slug)
            return None

        results = decoded.get("results") or []
        if not isinstance(results, list) or not results:
            ctx.info(f"urlscan.io has no search results for {value}.", self.slug)
            return None

        return decoded

    def _build_search_query(self, event_type: str, value: str) -> str | None:
        if event_type == "domain":
            return f"domain:{value}"
        if event_type == "url":
            return f"page.url:{value}"
        return None

    def _events_from_payload(
        self,
        payload: dict[str, Any],
        parent_event: ScanEvent,
        ctx,
    ) -> list[ScanEvent]:
        results = payload.get("results")
        if not isinstance(results, list) or not results:
            return []

        events: list[ScanEvent] = [
            ScanEvent(
                event_type="raw_rir_data",
                value=json.dumps(results, separators=(",", ":"), sort_keys=True),
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=80,
                visibility=100,
                risk_score=0,
                tags=["urlscan", "raw"],
                raw_payload={"result_count": len(results)},
            )
        ]

        linked_urls: set[str] = set()
        locations: set[str] = set()
        domains: set[str] = set()
        asns: set[str] = set()
        servers: set[str] = set()

        target_scope = parent_event.value.strip().lower()

        for result in results:
            if not isinstance(result, dict):
                continue

            page = result.get("page")
            if not isinstance(page, dict):
                continue

            domain = self._normalize_hostname(page.get("domain"))
            if not domain:
                continue

            if parent_event.event_type == "domain" and not self._matches_host_scope(target_scope, domain):
                continue

            if parent_event.event_type == "domain" and domain != target_scope:
                domains.add(domain)

            asn = str(page.get("asn", "") or "").strip().upper()
            if asn.startswith("AS"):
                asn = asn[2:]
            if asn:
                asns.add(asn)

            location = ", ".join(
                part for part in [
                    str(page.get("city", "") or "").strip(),
                    str(page.get("country", "") or "").strip(),
                ]
                if part
            )
            if location:
                locations.add(location)

            server = str(page.get("server", "") or "").strip()
            if server:
                servers.add(server)

            task = result.get("task")
            if not isinstance(task, dict):
                continue

            task_url = str(task.get("url", "") or "").strip()
            if not task_url:
                continue

            host = self._hostname_from_url(task_url)
            if parent_event.event_type == "domain":
                if self._matches_host_scope(target_scope, host):
                    linked_urls.add(task_url)
            else:
                linked_urls.add(task_url)
                if domain != target_scope:
                    domains.add(domain)

        for linked_url in sorted(linked_urls):
            events.append(ScanEvent(
                event_type="linked_url_internal",
                value=linked_url,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=72,
                visibility=100,
                risk_score=10,
                tags=["urlscan", "url"],
                raw_payload={"parent": parent_event.value},
            ))

        for location in sorted(locations):
            events.append(ScanEvent(
                event_type="physical_location",
                value=location,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=70,
                visibility=100,
                risk_score=0,
                tags=["urlscan", "geo"],
                raw_payload={"parent": parent_event.value},
            ))

        verify_hostnames = self._truthy(ctx.module_settings_for(self.slug).get("verify_hostnames", True))
        for domain in sorted(domains):
            if verify_hostnames and not self._resolves(domain):
                event_type = "internet_name_unresolved"
            else:
                event_type = "internet_name"

            events.append(ScanEvent(
                event_type=event_type,
                value=domain,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=74,
                visibility=100,
                risk_score=10,
                tags=["urlscan", "domain"],
                raw_payload={"parent": parent_event.value},
            ))

            if self._looks_like_domain(domain):
                events.append(ScanEvent(
                    event_type="domain_name",
                    value=domain,
                    source_module=self.slug,
                    root_target=ctx.root_target,
                    parent_event_id=parent_event.event_id,
                    confidence=74,
                    visibility=100,
                    risk_score=8,
                    tags=["urlscan", "domain_name"],
                    raw_payload={"parent": parent_event.value},
                ))

        for asn in sorted(asns):
            events.append(ScanEvent(
                event_type="bgp_as_member",
                value=asn,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=80,
                visibility=100,
                risk_score=0,
                tags=["urlscan", "asn"],
                raw_payload={"parent": parent_event.value},
            ))

        for server in sorted(servers):
            events.append(ScanEvent(
                event_type="webserver_banner",
                value=server,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=75,
                visibility=100,
                risk_score=0,
                tags=["urlscan", "server"],
                raw_payload={"parent": parent_event.value},
            ))

        return events

    def _resolves(self, hostname: str) -> bool:
        try:
            socket.getaddrinfo(hostname, None)
            return True
        except OSError:
            return False

    def _truthy(self, value: Any) -> bool:
        return str(value).strip().lower() not in {"0", "false", "no", "off", ""}

    def _matches_host_scope(self, target_host: str, candidate_host: str) -> bool:
        if not target_host or not candidate_host:
            return False
        if candidate_host == target_host:
            return True
        return candidate_host.endswith("." + target_host)

    def _hostname_from_url(self, value: str) -> str:
        parsed = urllib.parse.urlparse(value)
        return self._normalize_hostname(parsed.hostname)

    def _normalize_hostname(self, value: Any) -> str:
        return str(value or "").strip().lower().rstrip(".")

    def _looks_like_domain(self, value: str) -> bool:
        parts = value.split(".")
        return len(parts) >= 2 and all(part and part.replace("-", "").isalnum() for part in parts)
