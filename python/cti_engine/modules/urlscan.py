"""urlscan.io module for the first-party CTI engine."""

from __future__ import annotations

import json
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
        "ip",
        "internet_name",
        "linked_url_internal",
        "malicious_domain",
        "malicious_url",
    }
    requires_key = True

    DEFAULT_BASE_URL = "https://urlscan.io/api/v1"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        api_config = ctx.api_config_for(self.slug)
        api_key = str(api_config.get("api_key", "")).strip()
        if not api_key:
            ctx.error("urlscan.io module requires an API key.", self.slug)
            return

        settings = ctx.module_settings_for(self.slug)
        timeout = int(
            settings.get("timeout_seconds")
            or ctx.request.settings.global_settings.get("http_timeout", 15)
            or 15
        )
        result_limit = max(1, min(5, int(settings.get("result_limit", 1) or 1)))
        base_url = str(api_config.get("base_url", "")).strip() or self.DEFAULT_BASE_URL

        payload = self._fetch_payload(
            event.event_type,
            event.value,
            api_key,
            base_url,
            result_limit,
            timeout,
            ctx,
        )
        if payload is None:
            return

        for child in self._events_from_payload(payload, event, ctx):
            yield child

    def _fetch_payload(
        self,
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
            "API-Key": api_key,
            "Accept": "application/json",
            "User-Agent": "CTI Engine",
        }

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
        if not results:
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
        latest = ((payload.get("results") or [None])[0]) or {}
        task = latest.get("task") or {}
        page = latest.get("page") or {}
        verdicts = latest.get("verdicts") or {}
        overall = verdicts.get("overall") or {}

        is_malicious = bool(overall.get("malicious"))
        categories = [
            str(category).strip().lower()
            for category in (overall.get("categories") or [])
            if str(category).strip()
        ]
        risk_score = 85 if is_malicious else 5
        page_url = str(page.get("url") or parent_event.value).strip()
        page_domain = self._normalize_hostname(
            page.get("domain") or task.get("domain") or self._hostname_from_url(page_url)
        )
        page_ip = str(page.get("ip", "") or "").strip()
        scan_date = str(task.get("time", "") or "")
        country = str(page.get("country", "") or "")
        server = str(page.get("server", "") or "")

        base_tags = ["urlscan"] + categories[:5]
        summary_payload = {
            "scan_date": scan_date,
            "country": country,
            "server": server,
            "malicious": is_malicious,
            "categories": categories,
        }

        events: list[ScanEvent] = []
        if parent_event.event_type == "domain":
            if is_malicious:
                events.append(ScanEvent(
                    event_type="malicious_domain",
                    value=parent_event.value,
                    source_module=self.slug,
                    root_target=ctx.root_target,
                    parent_event_id=parent_event.event_id,
                    confidence=78,
                    visibility=100,
                    risk_score=risk_score,
                    tags=base_tags + ["domain"],
                    raw_payload=summary_payload,
                ))
            if page_url and page_url != parent_event.value:
                events.append(ScanEvent(
                    event_type="linked_url_internal",
                    value=page_url,
                    source_module=self.slug,
                    root_target=ctx.root_target,
                    parent_event_id=parent_event.event_id,
                    confidence=72,
                    visibility=100,
                    risk_score=20 if is_malicious else 10,
                    tags=base_tags + ["page_url"],
                    raw_payload=summary_payload,
                ))
        else:
            events.append(ScanEvent(
                event_type="malicious_url" if is_malicious else "linked_url_internal",
                value=page_url or parent_event.value,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=80 if is_malicious else 68,
                visibility=100,
                risk_score=risk_score,
                tags=base_tags + ["url"],
                raw_payload=summary_payload,
            ))

        if page_domain and page_domain != parent_event.value.strip().lower():
            events.append(ScanEvent(
                event_type="internet_name",
                value=page_domain,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=74,
                visibility=100,
                risk_score=12,
                tags=base_tags + ["domain"],
                raw_payload={"page_url": page_url},
            ))

        if page_ip and page_ip != parent_event.value:
            events.append(ScanEvent(
                event_type="ip",
                value=page_ip,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=78,
                visibility=100,
                risk_score=15,
                tags=base_tags + ["ip"],
                raw_payload={"page_domain": page_domain, "page_url": page_url},
            ))

        return events

    def _hostname_from_url(self, value: str) -> str:
        parsed = urllib.parse.urlparse(value)
        return self._normalize_hostname(parsed.hostname)

    def _normalize_hostname(self, value: Any) -> str:
        return str(value or "").strip().lower().rstrip(".")
