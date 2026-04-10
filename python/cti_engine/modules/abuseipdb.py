"""AbuseIPDB module for the first-party CTI engine."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, AsyncIterator

from ..events import ScanEvent
from ..module_base import BaseModule


class AbuseIpDbModule(BaseModule):
    slug = "abuseipdb"
    name = "AbuseIPDB"
    watched_types = {"ip"}
    produced_types = {
        "internet_name",
        "malicious_ip",
    }
    requires_key = True

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        api_config = ctx.api_config_for(self.slug)
        api_key = str(api_config.get("api_key", "")).strip()
        if not api_key:
            ctx.error("AbuseIPDB module requires an API key.", self.slug)
            return

        base_url = str(api_config.get("base_url", "")).strip() or "https://api.abuseipdb.com/api/v2"
        timeout = int(ctx.request.settings.global_settings.get("http_timeout", 15) or 15)
        payload = self._fetch_payload(base_url, event.value, api_key, timeout, ctx)
        if payload is None:
            return

        for child in self._events_from_payload(payload, event, ctx):
            yield child

    def _fetch_payload(
        self,
        base_url: str,
        ip_value: str,
        api_key: str,
        timeout: int,
        ctx,
    ) -> dict[str, Any] | None:
        params = urllib.parse.urlencode({
            "ipAddress": ip_value,
            "maxAgeInDays": 90,
            "verbose": "",
        })
        endpoint = f"{base_url.rstrip('/')}/check?{params}"
        headers = {
            "Key": api_key,
            "Accept": "application/json",
            "User-Agent": "CTI Engine",
        }

        ctx.info(f"Fetching AbuseIPDB data for {ip_value}.", self.slug)
        request = urllib.request.Request(endpoint, headers=headers, method="GET")

        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec - fixed provider URL
                status = int(getattr(response, "status", 200) or 200)
                content = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                ctx.info(f"AbuseIPDB has no data for {ip_value}.", self.slug)
                return None
            if exc.code == 429:
                ctx.error("Your request to AbuseIPDB was throttled.", self.slug)
                return None
            if exc.code in (401, 403):
                ctx.error("AbuseIPDB rejected the API key or access token.", self.slug)
                return None
            ctx.warning(f"AbuseIPDB request failed for {ip_value}: HTTP {exc.code}", self.slug)
            return None
        except Exception as exc:
            ctx.warning(f"AbuseIPDB request failed for {ip_value}: {exc}", self.slug)
            return None

        if status >= 400:
            ctx.warning(f"AbuseIPDB returned HTTP {status} for {ip_value}.", self.slug)
            return None

        try:
            decoded = json.loads(content)
        except json.JSONDecodeError as exc:
            ctx.error(f"AbuseIPDB returned invalid JSON: {exc}", self.slug)
            return None

        payload = decoded.get("data")
        if not isinstance(payload, dict):
            ctx.info(f"AbuseIPDB returned no check payload for {ip_value}.", self.slug)
            return None

        return payload

    def _events_from_payload(
        self,
        payload: dict[str, Any],
        parent_event: ScanEvent,
        ctx,
    ) -> list[ScanEvent]:
        events: list[ScanEvent] = []

        abuse_score = int(payload.get("abuseConfidenceScore", 0) or 0)
        total_reports = int(payload.get("totalReports", 0) or 0)
        domain = str(payload.get("domain", "") or "").strip().lower()
        isp = str(payload.get("isp", "") or "").strip()
        usage_type = str(payload.get("usageType", "") or "").strip()
        last_reported = str(payload.get("lastReportedAt", "") or "").strip()

        if abuse_score > 0 or total_reports > 0:
            tags = ["abuseipdb", "reported"]
            if usage_type:
                tags.append(usage_type.lower().replace(" ", "_"))

            raw_payload = {
                "abuse_confidence_score": abuse_score,
                "total_reports": total_reports,
            }
            if isp:
                raw_payload["isp"] = isp
            if last_reported:
                raw_payload["last_reported_at"] = last_reported

            events.append(ScanEvent(
                event_type="malicious_ip",
                value=parent_event.value,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=self._confidence_from_reports(total_reports),
                visibility=100,
                risk_score=max(0, min(100, abuse_score)),
                tags=tags,
                raw_payload=raw_payload,
            ))

        if domain and domain not in {"unknown", "n/a"} and domain != parent_event.value.strip().lower():
            events.append(ScanEvent(
                event_type="internet_name",
                value=domain,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=75,
                visibility=100,
                risk_score=10,
                tags=["abuseipdb", "domain"],
                raw_payload={"source_ip": parent_event.value},
            ))

        return events

    def _confidence_from_reports(self, total_reports: int) -> int:
        if total_reports <= 0:
            return 50
        return min(99, 60 + min(39, total_reports))
