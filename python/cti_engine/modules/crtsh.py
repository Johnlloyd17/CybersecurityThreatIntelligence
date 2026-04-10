"""crt.sh certificate transparency module for the first-party CTI engine."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, AsyncIterator

from ..events import ScanEvent
from ..module_base import BaseModule


class CrtShModule(BaseModule):
    slug = "crt-sh"
    name = "Certificate Transparency (crt.sh)"
    watched_types = {"domain"}
    produced_types = {"certificate_record", "internet_name"}
    requires_key = False

    DEFAULT_BASE_URL = "https://crt.sh"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        api_config = ctx.api_config_for(self.slug)
        settings = ctx.module_settings_for(self.slug)
        base_url = str(api_config.get("base_url", "")).strip() or self.DEFAULT_BASE_URL
        timeout = int(ctx.request.settings.global_settings.get("http_timeout", 25) or 25)

        payload = self._fetch_payload(event.value, base_url, timeout, ctx)
        if payload is None:
            return

        for child in self._events_from_payload(payload, event, settings, ctx):
            yield child

    def _fetch_payload(
        self,
        domain: str,
        base_url: str,
        timeout: int,
        ctx,
    ) -> list[dict[str, Any]] | None:
        endpoint = (
            f"{base_url.rstrip('/')}/?"
            f"{urllib.parse.urlencode({'q': '%.' + domain, 'output': 'json'})}"
        )
        ctx.info(f"Fetching crt.sh data for {domain}.", self.slug)
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
                ctx.info(f"crt.sh has no data for {domain}.", self.slug)
                return None
            if exc.code == 429:
                ctx.error("Your request to crt.sh was throttled.", self.slug)
                return None
            ctx.warning(f"crt.sh request failed for {domain}: HTTP {exc.code}", self.slug)
            return None
        except Exception as exc:
            ctx.warning(f"crt.sh request failed for {domain}: {exc}", self.slug)
            return None

        if status >= 400:
            ctx.warning(f"crt.sh returned HTTP {status} for {domain}.", self.slug)
            return None

        try:
            decoded = json.loads(content)
        except json.JSONDecodeError as exc:
            ctx.error(f"crt.sh returned invalid JSON: {exc}", self.slug)
            return None

        if not isinstance(decoded, list):
            ctx.info(f"crt.sh returned no certificate rows for {domain}.", self.slug)
            return None

        rows = [row for row in decoded if isinstance(row, dict)]
        if not rows:
            ctx.info(f"crt.sh returned no matching certificates for {domain}.", self.slug)
            return None

        return rows

    def _events_from_payload(
        self,
        payload: list[dict[str, Any]],
        parent_event: ScanEvent,
        settings: dict[str, Any],
        ctx,
    ) -> list[ScanEvent]:
        include_names = self._truthy(settings.get("verify_san", True))
        include_summary = self._truthy(settings.get("fetch_certs", True))

        names: list[str] = []
        seen_names: set[str] = set()
        issuers: list[str] = []
        seen_issuers: set[str] = set()

        for row in payload:
            issuer = str(row.get("issuer_name", "") or "").strip()
            if issuer and issuer not in seen_issuers:
                seen_issuers.add(issuer)
                issuers.append(issuer)

            candidates = []
            common_name = row.get("common_name")
            if common_name:
                candidates.append(common_name)
            name_value = row.get("name_value")
            if name_value:
                candidates.extend(str(name_value).splitlines())

            for candidate in candidates:
                normalized = self._normalize_dns_name(candidate)
                if not normalized or normalized == parent_event.value.lower() or normalized in seen_names:
                    continue
                seen_names.add(normalized)
                names.append(normalized)

        events: list[ScanEvent] = []
        if include_summary:
            events.append(ScanEvent(
                event_type="certificate_record",
                value=(
                    f"Domain {parent_event.value}: {len(payload)} certificate row(s) found; "
                    f"{len(names)} unique DNS name(s)"
                ),
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=85,
                visibility=100,
                risk_score=min(20, max(0, len(names) // 4)),
                tags=["crt-sh", "certificate", "transparency"],
                raw_payload={
                    "row_count": len(payload),
                    "dns_name_count": len(names),
                    "issuers": issuers[:10],
                },
            ))

        if include_names:
            for name in names[:50]:
                events.append(ScanEvent(
                    event_type="internet_name",
                    value=name,
                    source_module=self.slug,
                    root_target=ctx.root_target,
                    parent_event_id=parent_event.event_id,
                    confidence=74,
                    visibility=100,
                    risk_score=5,
                    tags=["crt-sh", "certificate", "dns_name"],
                    raw_payload={"source_domain": parent_event.value},
                ))

        return events

    def _normalize_dns_name(self, value: Any) -> str:
        normalized = str(value or "").strip().lower().rstrip(".")
        if normalized.startswith("*."):
            normalized = normalized[2:]
        return normalized

    def _truthy(self, value: Any) -> bool:
        return str(value).strip().lower() not in {"0", "false", "no", "off", ""}
