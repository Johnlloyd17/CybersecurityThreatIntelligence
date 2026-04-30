"""Hunter module for the first-party CTI engine."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, AsyncIterator

from ..events import ScanEvent
from ..module_base import BaseModule


class HunterModule(BaseModule):
    slug = "hunter"
    name = "Hunter"
    watched_types = {"domain", "email"}
    produced_types = {
        "raw_rir_data",
        "email",
        "email_generic",
        "company_name",
        "undeliverable_email_address",
        "disposable_email_address",
    }
    requires_key = True

    DEFAULT_BASE_URL = "https://api.hunter.io/v2"
    DEFAULT_GENERIC_LOCALS = {
        "abuse",
        "admin",
        "billing",
        "contact",
        "help",
        "hello",
        "hostmaster",
        "info",
        "mail",
        "marketing",
        "noc",
        "office",
        "postmaster",
        "privacy",
        "sales",
        "security",
        "support",
        "webmaster",
    }

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        api_config = ctx.api_config_for(self.slug)
        api_key = str(api_config.get("api_key", "")).strip()
        if not api_key:
            ctx.error("Hunter module requires an API key.", self.slug)
            return

        base_url = str(api_config.get("base_url", "")).strip() or self.DEFAULT_BASE_URL
        timeout = int(ctx.request.settings.global_settings.get("http_timeout", 15) or 15)

        if event.event_type == "domain":
            payload = self._fetch_domain_payload(event.value, api_key, base_url, timeout, ctx)
        elif event.event_type == "email":
            payload = self._fetch_email_payload(event.value, api_key, base_url, timeout, ctx)
        else:
            ctx.debug(f"Hunter does not handle event type '{event.event_type}'.", self.slug)
            return

        if payload is None:
            return

        for child in self._events_from_payload(payload, event, ctx):
            yield child

    def _fetch_domain_payload(
        self,
        domain: str,
        api_key: str,
        base_url: str,
        timeout: int,
        ctx,
    ) -> dict[str, Any] | None:
        endpoint = (
            f"{base_url.rstrip('/')}/domain-search?"
            f"{urllib.parse.urlencode({'domain': domain, 'api_key': api_key})}"
        )
        ctx.info(f"Fetching Hunter domain data for {domain}.", self.slug)
        return self._request_json(endpoint, timeout, ctx, domain)

    def _fetch_email_payload(
        self,
        email: str,
        api_key: str,
        base_url: str,
        timeout: int,
        ctx,
    ) -> dict[str, Any] | None:
        endpoint = (
            f"{base_url.rstrip('/')}/email-verifier?"
            f"{urllib.parse.urlencode({'email': email, 'api_key': api_key})}"
        )
        ctx.info(f"Fetching Hunter email data for {email}.", self.slug)
        return self._request_json(endpoint, timeout, ctx, email)

    def _request_json(self, endpoint: str, timeout: int, ctx, value: str) -> dict[str, Any] | None:
        request = urllib.request.Request(
            endpoint,
            headers={"Accept": "application/json", "User-Agent": "CTI Engine"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec - fixed provider URL
                status = int(getattr(response, "status", 200) or 200)
                content = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                ctx.info(f"Hunter has no data for {value}.", self.slug)
                return None
            if exc.code == 429:
                ctx.error("Your request to Hunter was throttled.", self.slug)
                return None
            if exc.code in (401, 403):
                ctx.error("Hunter rejected the API key.", self.slug)
                return None
            ctx.warning(f"Hunter request failed for {value}: HTTP {exc.code}", self.slug)
            return None
        except Exception as exc:
            ctx.warning(f"Hunter request failed for {value}: {exc}", self.slug)
            return None

        if status >= 400:
            ctx.warning(f"Hunter returned HTTP {status} for {value}.", self.slug)
            return None

        try:
            decoded = json.loads(content)
        except json.JSONDecodeError as exc:
            ctx.error(f"Hunter returned invalid JSON: {exc}", self.slug)
            return None

        if not isinstance(decoded, dict):
            return None
        data = decoded.get("data")
        return data if isinstance(data, dict) else None

    def _events_from_payload(
        self,
        payload: dict[str, Any],
        parent_event: ScanEvent,
        ctx,
    ) -> list[ScanEvent]:
        events: list[ScanEvent] = [
            ScanEvent(
                event_type="raw_rir_data",
                value=json.dumps(payload, ensure_ascii=False, sort_keys=True),
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=78,
                visibility=100,
                risk_score=0,
                tags=["hunter", "raw"],
                raw_payload={"query": parent_event.value},
            )
        ]

        if parent_event.event_type == "domain":
            org = str(payload.get("organization", "") or "").strip()
            if org:
                events.append(ScanEvent(
                    event_type="company_name",
                    value=org,
                    source_module=self.slug,
                    root_target=ctx.root_target,
                    parent_event_id=parent_event.event_id,
                    confidence=84,
                    visibility=100,
                    risk_score=0,
                    tags=["hunter", "organization"],
                    raw_payload={"source_domain": parent_event.value},
                ))

            seen_emails: set[str] = set()
            for row in payload.get("emails") or []:
                if not isinstance(row, dict):
                    continue
                email_value = str(row.get("value", "") or "").strip().lower()
                if not email_value or email_value in seen_emails:
                    continue
                seen_emails.add(email_value)

                local_part = email_value.split("@", 1)[0]
                is_generic = bool(row.get("generic")) or local_part in self.DEFAULT_GENERIC_LOCALS
                event_type = "email_generic" if is_generic else "email"
                events.append(ScanEvent(
                    event_type=event_type,
                    value=email_value,
                    source_module=self.slug,
                    root_target=ctx.root_target,
                    parent_event_id=parent_event.event_id,
                    confidence=85,
                    visibility=100,
                    risk_score=6 if is_generic else 0,
                    tags=["hunter", "email", "generic" if is_generic else "address"],
                    raw_payload={"source_domain": parent_event.value},
                ))
            return events

        result = str(payload.get("result", "") or "").strip().lower()
        status = str(payload.get("status", "") or "").strip().lower()
        risk = 0
        if result == "risky":
            risk = 35

        if result == "undeliverable" or status in {"invalid", "undeliverable"}:
            events.append(ScanEvent(
                event_type="undeliverable_email_address",
                value=parent_event.value,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=88,
                visibility=100,
                risk_score=max(risk, 20),
                tags=["hunter", "email", "undeliverable"],
                raw_payload={"result": result, "status": status},
            ))

        if bool(payload.get("disposable")):
            events.append(ScanEvent(
                event_type="disposable_email_address",
                value=parent_event.value,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=85,
                visibility=100,
                risk_score=max(risk, 35),
                tags=["hunter", "email", "disposable"],
                raw_payload={"result": result, "status": status},
            ))

        return events
