"""EmailRep module with SpiderFoot-style reputation behavior."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, AsyncIterator

from ..events import ScanEvent
from ..module_base import BaseModule


class EmailRepModule(BaseModule):
    slug = "emailrep"
    name = "EmailRep"
    watched_types = {"email"}
    produced_types = {"raw_rir_data", "malicious_email_address", "breached_email_address"}
    requires_key = False

    DEFAULT_BASE_URL = "https://emailrep.io"

    def __init__(self) -> None:
        self._warned_missing_key = False

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        api_config = ctx.api_config_for(self.slug)
        api_key = str(api_config.get("api_key", "")).strip()
        base_url = str(api_config.get("base_url", "")).strip() or self.DEFAULT_BASE_URL
        timeout = int(ctx.request.settings.global_settings.get("http_timeout", 15) or 15)

        if not api_key and not self._warned_missing_key:
            ctx.warning(
                "EmailRep is enabled without an API key; requests may be rate limited.",
                self.slug,
            )
            self._warned_missing_key = True

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
    ) -> dict[str, Any] | None:
        endpoint = f"{base_url.rstrip('/')}/{urllib.parse.quote(email, safe='')}"
        headers = {
            "Accept": "application/json",
            "User-Agent": "CTI Engine",
        }
        if api_key:
            headers["Key"] = api_key

        ctx.info(f"Fetching EmailRep data for {email}.", self.slug)
        request = urllib.request.Request(endpoint, headers=headers, method="GET")

        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec - fixed provider URL
                status = int(getattr(response, "status", 200) or 200)
                content = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            if exc.code == 400:
                ctx.error("EmailRep rejected the request as invalid.", self.slug)
                return None
            if exc.code in (401, 403):
                ctx.error("EmailRep rejected the API key.", self.slug)
                return None
            if exc.code == 404:
                ctx.info(f"EmailRep has no data for {email}.", self.slug)
                return None
            if exc.code == 429:
                ctx.error("Your request to EmailRep was throttled.", self.slug)
                return None
            ctx.warning(f"EmailRep request failed for {email}: HTTP {exc.code}", self.slug)
            return None
        except Exception as exc:
            ctx.warning(f"EmailRep request failed for {email}: {exc}", self.slug)
            return None

        if status != 200:
            ctx.warning(f"EmailRep returned HTTP {status} for {email}.", self.slug)
            return None

        try:
            decoded = json.loads(content)
        except json.JSONDecodeError as exc:
            ctx.error(f"EmailRep returned invalid JSON: {exc}", self.slug)
            return None

        return decoded if isinstance(decoded, dict) else None

    def _events_from_payload(
        self,
        payload: dict[str, Any],
        parent_event: ScanEvent,
        ctx,
    ) -> list[ScanEvent]:
        details = payload.get("details") if isinstance(payload.get("details"), dict) else {}
        if not details:
            return []

        credentials_leaked = bool(details.get("credentials_leaked"))
        malicious_activity = bool(details.get("malicious_activity"))
        if not credentials_leaked and not malicious_activity:
            return []

        events: list[ScanEvent] = []
        if credentials_leaked:
            events.append(ScanEvent(
                event_type="breached_email_address",
                value=f"{parent_event.value} [Unknown]",
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=88,
                visibility=100,
                risk_score=60,
                tags=["emailrep", "credentials_leaked"],
                raw_payload={"query": parent_event.value},
            ))

        if malicious_activity:
            events.append(ScanEvent(
                event_type="malicious_email_address",
                value=f"EmailRep [{parent_event.value}]",
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=90,
                visibility=100,
                risk_score=80,
                tags=["emailrep", "malicious_activity"],
                raw_payload={"query": parent_event.value},
            ))

        events.append(ScanEvent(
            event_type="raw_rir_data",
            value=json.dumps(payload, ensure_ascii=False, sort_keys=True),
            source_module=self.slug,
            root_target=ctx.root_target,
            parent_event_id=parent_event.event_id,
            confidence=78,
            visibility=100,
            risk_score=0,
            tags=["emailrep", "raw"],
            raw_payload={"query": parent_event.value},
        ))

        return events
