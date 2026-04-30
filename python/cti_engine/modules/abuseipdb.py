"""AbuseIPDB module for the first-party CTI engine.

This implementation intentionally follows SpiderFoot's blacklist-first path for
IP reputation checks, rather than using the richer single-IP `check` endpoint.
That keeps the default routed behavior closer to what SpiderFoot itself emits.
"""

from __future__ import annotations

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
        "blacklisted_ip",
        "malicious_ip",
    }
    requires_key = True

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        api_config = ctx.api_config_for(self.slug)
        api_key = str(api_config.get("api_key", "")).strip()
        if not api_key:
            ctx.error("AbuseIPDB module requires an API key.", self.slug)
            return

        module_settings = ctx.module_settings_for(self.slug)
        base_url = str(api_config.get("base_url", "")).strip() or "https://api.abuseipdb.com/api/v2"
        timeout = max(15, int(ctx.request.settings.global_settings.get("http_timeout", 15) or 15))
        confidence_minimum = max(
            1,
            min(
                100,
                int(
                    module_settings.get("min_confidence")
                    or module_settings.get("confidenceminimum")
                    or 90
                ),
            ),
        )
        limit = max(
            1,
            min(
                10000,
                int(
                    module_settings.get("max_results")
                    or module_settings.get("limit")
                    or 10000
                ),
            ),
        )

        blacklist = self._fetch_blacklist(
            base_url=base_url,
            api_key=api_key,
            timeout=timeout,
            confidence_minimum=confidence_minimum,
            limit=limit,
            ctx=ctx,
        )
        if blacklist is None:
            return

        for child in self._events_from_blacklist(blacklist, event, ctx):
            yield child

    def _fetch_blacklist(
        self,
        *,
        base_url: str,
        api_key: str,
        timeout: int,
        confidence_minimum: int,
        limit: int,
        ctx,
    ) -> set[str] | None:
        params = urllib.parse.urlencode({
            "confidenceMinimum": confidence_minimum,
            "limit": limit,
            "plaintext": "1",
        })
        endpoint = f"{base_url.rstrip('/')}/blacklist?{params}"
        headers = {
            "Key": api_key,
            "Accept": "text/plain",
            "User-Agent": "CTI Engine",
        }

        ctx.info("Fetching AbuseIPDB blacklist data.", self.slug)
        request = urllib.request.Request(endpoint, headers=headers, method="GET")

        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec - fixed provider URL
                status = int(getattr(response, "status", 200) or 200)
                content = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                ctx.error("Your request to AbuseIPDB was throttled.", self.slug)
                return None
            if exc.code in (401, 403):
                ctx.error("AbuseIPDB rejected the API key or access token.", self.slug)
                return None
            ctx.warning(f"AbuseIPDB request failed: HTTP {exc.code}", self.slug)
            return None
        except Exception as exc:
            ctx.warning(f"AbuseIPDB request failed: {exc}", self.slug)
            return None

        if status >= 400:
            ctx.warning(f"AbuseIPDB returned HTTP {status}.", self.slug)
            return None

        return self._parse_blacklist(content)

    def _parse_blacklist(self, plaintext: str) -> set[str]:
        entries: set[str] = set()
        for line in str(plaintext or "").splitlines():
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            entries.add(value)
        return entries

    def _events_from_blacklist(
        self,
        blacklist: set[str],
        parent_event: ScanEvent,
        ctx,
    ) -> list[ScanEvent]:
        if parent_event.value not in blacklist:
            return []

        shared_payload = {
            "provider": "abuseipdb",
            "lookup_mode": "blacklist",
            "check_url": f"https://www.abuseipdb.com/check/{parent_event.value}",
        }

        return [
            ScanEvent(
                event_type="malicious_ip",
                value=parent_event.value,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=95,
                visibility=100,
                risk_score=90,
                tags=["abuseipdb", "malicious"],
                raw_payload=shared_payload,
            ),
            ScanEvent(
                event_type="blacklisted_ip",
                value=parent_event.value,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=95,
                visibility=100,
                risk_score=85,
                tags=["abuseipdb", "blacklist"],
                raw_payload=shared_payload,
            ),
        ]
