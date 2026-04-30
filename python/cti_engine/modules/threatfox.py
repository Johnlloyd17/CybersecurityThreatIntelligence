"""ThreatFox module with SpiderFoot-style blacklist signaling."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, AsyncIterator

from ..events import ScanEvent
from ..module_base import BaseModule


class ThreatFoxModule(BaseModule):
    slug = "threatfox"
    name = "ThreatFox"
    watched_types = {"ip", "affiliate_ipaddr", "domain", "url", "hash"}
    produced_types = {
        "blacklisted_ip",
        "blacklisted_affiliate_ipaddr",
        "blacklisted_internet_name",
        "blacklisted_url",
        "blacklisted_hash",
        "malicious_ip",
        "malicious_affiliate_ipaddr",
        "malicious_internet_name",
        "malicious_url",
        "malicious_hash",
    }
    requires_key = False

    DEFAULT_BASE_URL = "https://threatfox-api.abuse.ch/api/v1/"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        if event.event_type == "affiliate_ipaddr":
            settings = ctx.module_settings_for(self.slug)
            if not self._truthy(settings.get("checkaffiliates", True)):
                return

        timeout = int(ctx.request.settings.global_settings.get("http_timeout", 15) or 15)
        payload = self._fetch_payload(event.value, timeout, ctx)
        if payload is None:
            return

        for child in self._events_from_payload(payload, event, ctx):
            yield child

    def _fetch_payload(self, value: str, timeout: int, ctx) -> list[dict[str, Any]] | None:
        request = urllib.request.Request(
            self.DEFAULT_BASE_URL,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "CTI Engine",
            },
            data=json.dumps({"query": "search_ioc", "search_term": value}).encode("utf-8"),
            method="POST",
        )
        ctx.info(f"Fetching ThreatFox data for {value}.", self.slug)

        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec - fixed provider URL
                status = int(getattr(response, "status", 200) or 200)
                content = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                ctx.error("Your request to ThreatFox was throttled.", self.slug)
                return None
            ctx.warning(f"ThreatFox request failed for {value}: HTTP {exc.code}", self.slug)
            return None
        except Exception as exc:
            ctx.warning(f"ThreatFox request failed for {value}: {exc}", self.slug)
            return None

        if status != 200:
            ctx.warning(f"ThreatFox returned HTTP {status} for {value}.", self.slug)
            return None

        try:
            decoded = json.loads(content)
        except json.JSONDecodeError as exc:
            ctx.error(f"ThreatFox returned invalid JSON: {exc}", self.slug)
            return None

        query_status = str(decoded.get("query_status", "") or "").strip().lower()
        if query_status == "no_result":
            ctx.info(f"ThreatFox has no data for {value}.", self.slug)
            return None
        if query_status != "ok":
            ctx.warning(f"ThreatFox query failed with status '{query_status}'.", self.slug)
            return None

        data = decoded.get("data")
        if not isinstance(data, list) or not data:
            return None

        return [row for row in data if isinstance(row, dict)]

    def _events_from_payload(
        self,
        payload: list[dict[str, Any]],
        parent_event: ScanEvent,
        ctx,
    ) -> list[ScanEvent]:
        pair = self._event_pair_for(parent_event.event_type)
        if pair is None:
            return []

        malicious_type, blacklisted_type = pair
        detail_url = (
            "https://threatfox.abuse.ch/browse.php?search=ioc:"
            + urllib.parse.quote(str(parent_event.value or "").strip(), safe="")
        )
        value = f"ThreatFox [{parent_event.value}]"

        confidence_levels: list[int] = []
        for row in payload:
            try:
                confidence = int(row.get("confidence_level", 0) or 0)
            except Exception:
                confidence = 0
            if confidence:
                confidence_levels.append(confidence)

        confidence = int(sum(confidence_levels) / len(confidence_levels)) if confidence_levels else 75
        raw = {"match_count": len(payload), "source_url": detail_url}
        return [
            ScanEvent(
                event_type=malicious_type,
                value=value,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=confidence,
                visibility=100,
                risk_score=85,
                tags=["threatfox", "ioc", "malicious"],
                raw_payload=raw,
            ),
            ScanEvent(
                event_type=blacklisted_type,
                value=value,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=confidence,
                visibility=100,
                risk_score=80,
                tags=["threatfox", "ioc", "blacklist"],
                raw_payload=raw,
            ),
        ]

    def _event_pair_for(self, event_type: str) -> tuple[str, str] | None:
        mapping = {
            "domain": ("malicious_internet_name", "blacklisted_internet_name"),
            "ip": ("malicious_ip", "blacklisted_ip"),
            "affiliate_ipaddr": ("malicious_affiliate_ipaddr", "blacklisted_affiliate_ipaddr"),
            "url": ("malicious_url", "blacklisted_url"),
            "hash": ("malicious_hash", "blacklisted_hash"),
        }
        return mapping.get(str(event_type or "").strip().lower())

    def _truthy(self, value: Any) -> bool:
        return str(value).strip().lower() not in {"0", "false", "no", "off", ""}
