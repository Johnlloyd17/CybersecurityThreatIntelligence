"""Have I Been Pwned module for the first-party CTI engine."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, AsyncIterator

from ..events import ScanEvent
from ..module_base import BaseModule


class HaveIBeenPwnedModule(BaseModule):
    slug = "haveibeenpwned"
    name = "Have I Been Pwned"
    watched_types = {"email"}
    produced_types = {"raw_rir_data", "breached_email_address"}
    requires_key = True

    DEFAULT_BASE_URL = "https://haveibeenpwned.com/api/v3"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        api_config = ctx.api_config_for(self.slug)
        api_key = str(api_config.get("api_key", "")).strip()
        if not api_key:
            ctx.error("Have I Been Pwned module requires an API key.", self.slug)
            return

        base_url = str(api_config.get("base_url", "")).strip() or self.DEFAULT_BASE_URL
        timeout = int(ctx.request.settings.global_settings.get("http_timeout", 15) or 15)
        payload = self._fetch_payload(event.value, api_key, base_url, timeout, ctx)
        if payload is None:
            return

        for child in self._events_from_payload(payload, event, ctx):
            yield child

    def _fetch_payload(
        self,
        email: str,
        api_key: str,
        base_url: str,
        timeout: int,
        ctx,
    ) -> list[dict[str, Any]] | None:
        endpoint = (
            f"{base_url.rstrip('/')}/breachedaccount/"
            f"{urllib.parse.quote(email, safe='')}?truncateResponse=false"
        )
        headers = {
            "hibp-api-key": api_key,
            "user-agent": "CTI Engine",
            "Accept": "application/json",
        }
        ctx.info(f"Fetching Have I Been Pwned data for {email}.", self.slug)
        request = urllib.request.Request(endpoint, headers=headers, method="GET")

        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec - fixed provider URL
                status = int(getattr(response, "status", 200) or 200)
                content = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                ctx.info(f"Have I Been Pwned has no breach data for {email}.", self.slug)
                return None
            if exc.code == 429:
                ctx.error("Your request to Have I Been Pwned was throttled.", self.slug)
                return None
            if exc.code in (401, 403):
                ctx.error("Have I Been Pwned rejected the API key.", self.slug)
                return None
            ctx.warning(f"Have I Been Pwned request failed for {email}: HTTP {exc.code}", self.slug)
            return None
        except Exception as exc:
            ctx.warning(f"Have I Been Pwned request failed for {email}: {exc}", self.slug)
            return None

        if status >= 400:
            ctx.warning(f"Have I Been Pwned returned HTTP {status} for {email}.", self.slug)
            return None

        try:
            decoded = json.loads(content)
        except json.JSONDecodeError as exc:
            ctx.error(f"Have I Been Pwned returned invalid JSON: {exc}", self.slug)
            return None

        return decoded if isinstance(decoded, list) else None

    def _events_from_payload(
        self,
        payload: list[dict[str, Any]],
        parent_event: ScanEvent,
        ctx,
    ) -> list[ScanEvent]:
        if not payload:
            return []

        breach_names = []
        exposed_data: set[str] = set()
        for breach in payload:
            if not isinstance(breach, dict):
                continue
            name = str(breach.get("Name", "") or breach.get("name", "") or "").strip()
            if name:
                breach_names.append(name)
            for field in breach.get("DataClasses") or []:
                field_value = str(field or "").strip()
                if field_value:
                    exposed_data.add(field_value)

        summary_payload = {
            "breach_count": len(payload),
            "breach_names": breach_names,
            "data_classes": sorted(exposed_data),
            "results": payload,
        }

        return [
            ScanEvent(
                event_type="raw_rir_data",
                value=json.dumps(summary_payload, ensure_ascii=False, sort_keys=True),
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=85,
                visibility=100,
                risk_score=0,
                tags=["hibp", "raw"],
                raw_payload={"query": parent_event.value},
            ),
            ScanEvent(
                event_type="breached_email_address",
                value=parent_event.value,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=95,
                visibility=100,
                risk_score=min(90, 30 + len(payload) * 10),
                tags=["hibp", "email", "breach"],
                raw_payload=summary_payload,
            ),
        ]
