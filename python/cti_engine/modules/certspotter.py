"""CertSpotter certificate transparency module for the first-party CTI engine."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, AsyncIterator

from ..events import ScanEvent
from ..module_base import BaseModule


class CertSpotterModule(BaseModule):
    slug = "certspotter"
    name = "CertSpotter"
    watched_types = {"domain"}
    produced_types = {"certificate_record", "internet_name"}
    requires_key = False

    DEFAULT_BASE_URL = "https://api.certspotter.com/v1"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        api_config = ctx.api_config_for(self.slug)
        settings = ctx.module_settings_for(self.slug)
        api_key = str(api_config.get("api_key", "")).strip()
        base_url = str(api_config.get("base_url", "")).strip() or self.DEFAULT_BASE_URL
        timeout = int(ctx.request.settings.global_settings.get("http_timeout", 15) or 15)
        max_pages = max(1, min(20, int(settings.get("max_pages", 1) or 1)))

        payload = self._fetch_payload(event.value, api_key, base_url, timeout, max_pages, ctx)
        if not payload:
            return

        for child in self._events_from_payload(payload, event, settings, ctx):
            yield child

    def _fetch_payload(
        self,
        domain: str,
        api_key: str,
        base_url: str,
        timeout: int,
        max_pages: int,
        ctx,
    ) -> list[dict[str, Any]] | None:
        issuances: list[dict[str, Any]] = []
        next_url = (
            f"{base_url.rstrip('/')}/issuances?"
            f"{urllib.parse.urlencode({'domain': domain, 'include_subdomains': 'true', 'expand': 'dns_names'})}"
        )
        headers = {
            "Accept": "application/json",
            "User-Agent": "CTI Engine",
        }
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        page = 0
        while next_url and page < max_pages:
            page += 1
            ctx.info(f"Fetching CertSpotter data for {domain} (page {page}).", self.slug)
            request = urllib.request.Request(next_url, headers=headers, method="GET")

            try:
                with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec - fixed provider URL
                    status = int(getattr(response, "status", 200) or 200)
                    content = response.read().decode("utf-8", errors="replace")
                    next_url = self._extract_next_link(str(response.headers.get("Link", "") or ""))
            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    ctx.info(f"CertSpotter has no data for {domain}.", self.slug)
                    return None
                if exc.code == 429:
                    ctx.error("Your request to CertSpotter was throttled.", self.slug)
                    return None
                if exc.code in (401, 403):
                    ctx.error("CertSpotter rejected the API key or access token.", self.slug)
                    return None
                ctx.warning(f"CertSpotter request failed for {domain}: HTTP {exc.code}", self.slug)
                return None
            except Exception as exc:
                ctx.warning(f"CertSpotter request failed for {domain}: {exc}", self.slug)
                return None

            if status >= 400:
                ctx.warning(f"CertSpotter returned HTTP {status} for {domain}.", self.slug)
                return None

            try:
                decoded = json.loads(content)
            except json.JSONDecodeError as exc:
                ctx.error(f"CertSpotter returned invalid JSON: {exc}", self.slug)
                return None

            if not isinstance(decoded, list):
                ctx.error("CertSpotter returned an unexpected payload shape.", self.slug)
                return None

            issuances.extend([row for row in decoded if isinstance(row, dict)])
            if not decoded:
                break

        if not issuances:
            ctx.info(f"CertSpotter found no certificate issuances for {domain}.", self.slug)
            return None

        return issuances

    def _events_from_payload(
        self,
        payload: list[dict[str, Any]],
        parent_event: ScanEvent,
        settings: dict[str, Any],
        ctx,
    ) -> list[ScanEvent]:
        verify_alt_names = self._truthy(settings.get("verify_alt_names", True))
        expiry_days = max(0, int(settings.get("cert_expiry_days", 30) or 30))

        dns_names: list[str] = []
        seen_names: set[str] = set()
        issuers: list[str] = []
        seen_issuers: set[str] = set()
        expiring_count = 0

        for issuance in payload:
            issuer = issuance.get("issuer") or {}
            issuer_name = str(issuer.get("O") or issuer.get("CN") or "").strip()
            if issuer_name and issuer_name not in seen_issuers:
                seen_issuers.add(issuer_name)
                issuers.append(issuer_name)

            not_after = self._parse_datetime(str(issuance.get("not_after", "") or ""))
            if not_after is not None and expiry_days > 0:
                delta_days = (not_after - datetime.now(timezone.utc)).total_seconds() / 86400
                if delta_days <= expiry_days:
                    expiring_count += 1

            for raw_name in issuance.get("dns_names") or []:
                name = self._normalize_dns_name(raw_name)
                if not name or name == parent_event.value.lower() or name in seen_names:
                    continue
                seen_names.add(name)
                dns_names.append(name)

        risk_score = 25 if expiring_count > 0 else min(15, max(0, len(dns_names) // 5))
        tags = ["certspotter", "certificate", "transparency"]
        if expiring_count > 0:
            tags.append("expiring")

        summary_parts = [
            f"Domain {parent_event.value}: {len(payload)} certificate issuance(s) found",
            f"{len(dns_names)} unique DNS name(s)",
        ]
        if issuers:
            summary_parts.append("Issuers: " + ", ".join(issuers[:5]))
        if expiring_count > 0:
            summary_parts.append(f"{expiring_count} certificate(s) expiring within {expiry_days} day(s)")

        events: list[ScanEvent] = [
            ScanEvent(
                event_type="certificate_record",
                value="; ".join(summary_parts),
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=88,
                visibility=100,
                risk_score=risk_score,
                tags=tags,
                raw_payload={
                    "issuance_count": len(payload),
                    "dns_name_count": len(dns_names),
                    "issuers": issuers[:10],
                    "expiring_count": expiring_count,
                },
            )
        ]

        if verify_alt_names:
            for dns_name in dns_names[:50]:
                events.append(ScanEvent(
                    event_type="internet_name",
                    value=dns_name,
                    source_module=self.slug,
                    root_target=ctx.root_target,
                    parent_event_id=parent_event.event_id,
                    confidence=76,
                    visibility=100,
                    risk_score=5,
                    tags=["certspotter", "certificate", "dns_name"],
                    raw_payload={"source_domain": parent_event.value},
                ))

        return events

    def _extract_next_link(self, header_value: str) -> str | None:
        if not header_value:
            return None
        match = re.search(r"<([^>]+)>;\s*rel=\"next\"", header_value)
        if not match:
            return None
        return match.group(1).strip() or None

    def _normalize_dns_name(self, value: Any) -> str:
        normalized = str(value or "").strip().lower().rstrip(".")
        if normalized.startswith("*."):
            normalized = normalized[2:]
        return normalized

    def _truthy(self, value: Any) -> bool:
        return str(value).strip().lower() not in {"0", "false", "no", "off", ""}

    def _parse_datetime(self, value: str) -> datetime | None:
        if not value:
            return None
        normalized = value.strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
