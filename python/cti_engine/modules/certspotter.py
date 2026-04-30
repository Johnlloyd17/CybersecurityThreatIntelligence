"""CertSpotter certificate transparency module for the first-party CTI engine."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import ipaddress
import json
import re
import socket
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
    produced_types = {
        "raw_rir_data",
        "ssl_certificate_raw",
        "ssl_certificate_issuer",
        "ssl_certificate_issued",
        "ssl_certificate_expired",
        "ssl_certificate_expiring",
        "internet_name",
        "internet_name_unresolved",
        "domain_name",
        "co_hosted_site",
        "co_hosted_site_domain",
    }
    requires_key = False

    DEFAULT_BASE_URL = "https://api.certspotter.com/v1"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        api_config = ctx.api_config_for(self.slug)
        settings = ctx.module_settings_for(self.slug)
        api_key = str(api_config.get("api_key", "")).strip()
        base_url = str(api_config.get("base_url", "")).strip() or self.DEFAULT_BASE_URL
        timeout = int(ctx.request.settings.global_settings.get("http_timeout", 15) or 15)
        max_pages = max(1, min(20, int(settings.get("max_pages", 20) or 20)))

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
            f"{urllib.parse.urlencode({'domain': domain, 'include_subdomains': 'true'})}"
            "&expand=dns_names&expand=issuer&expand=cert"
        )
        headers = {
            "Accept": "application/json",
            "User-Agent": "CTI Engine",
        }
        if api_key:
            encoded = base64.b64encode(f"{api_key}:".encode("utf-8")).decode("ascii")
            headers["Authorization"] = f"Basic {encoded}"

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
        verify_names = self._truthy(settings.get("verify", settings.get("verify_alt_names", True)))
        expiry_days = max(0, int(settings.get("certexpiringdays", settings.get("cert_expiry_days", 30)) or 30))

        target_domain = parent_event.value.strip().lower()
        hosts: list[str] = []
        seen_hosts: set[str] = set()
        events: list[ScanEvent] = [
            ScanEvent(
                event_type="raw_rir_data",
                value=json.dumps(payload, ensure_ascii=False),
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=85,
                visibility=100,
                risk_score=0,
                tags=["certspotter", "raw"],
                raw_payload={"row_count": len(payload)},
            )
        ]
        seen_raw_certs: set[str] = set()
        seen_issuers: set[str] = set()

        for issuance in payload:
            for raw_name in issuance.get("dns_names") or []:
                name = self._normalize_dns_name(raw_name)
                if not name or name == target_domain or name in seen_hosts:
                    continue
                seen_hosts.add(name)
                hosts.append(name)

            issuer = issuance.get("issuer") or {}
            issuer_name = str(issuer.get("O") or issuer.get("CN") or "").strip()
            if issuer_name and issuer_name not in seen_issuers:
                seen_issuers.add(issuer_name)
                events.append(ScanEvent(
                    event_type="ssl_certificate_issuer",
                    value=issuer_name,
                    source_module=self.slug,
                    root_target=ctx.root_target,
                    parent_event_id=parent_event.event_id,
                    confidence=84,
                    visibility=100,
                    risk_score=0,
                    tags=["certspotter", "certificate", "issuer"],
                    raw_payload={"source_domain": parent_event.value},
                ))

            cert_info = issuance.get("cert") or {}
            cert_data = str(cert_info.get("data", "") or "").strip()
            if cert_data:
                pem = f"-----BEGIN CERTIFICATE-----\n{cert_data}\n-----END CERTIFICATE-----"
                if pem not in seen_raw_certs:
                    seen_raw_certs.add(pem)
                    events.append(ScanEvent(
                        event_type="ssl_certificate_raw",
                        value=pem,
                        source_module=self.slug,
                        root_target=ctx.root_target,
                        parent_event_id=parent_event.event_id,
                        confidence=86,
                        visibility=100,
                        risk_score=0,
                        tags=["certspotter", "certificate", "raw"],
                        raw_payload={"source_domain": parent_event.value},
                    ))

            issued_value = str(cert_info.get("not_before") or issuance.get("not_before") or "").strip()
            if issued_value:
                events.append(ScanEvent(
                    event_type="ssl_certificate_issued",
                    value=issued_value,
                    source_module=self.slug,
                    root_target=ctx.root_target,
                    parent_event_id=parent_event.event_id,
                    confidence=82,
                    visibility=100,
                    risk_score=0,
                    tags=["certspotter", "certificate", "issued"],
                    raw_payload={"source_domain": parent_event.value},
                ))

            not_after = self._parse_datetime(str(issuance.get("not_after", "") or ""))
            if not_after is None:
                continue

            expiry_str = not_after.isoformat()
            if not_after <= datetime.now(timezone.utc):
                events.append(ScanEvent(
                    event_type="ssl_certificate_expired",
                    value=expiry_str,
                    source_module=self.slug,
                    root_target=ctx.root_target,
                    parent_event_id=parent_event.event_id,
                    confidence=88,
                    visibility=100,
                    risk_score=40,
                    tags=["certspotter", "certificate", "expired"],
                    raw_payload={"source_domain": parent_event.value},
                ))
                continue

            if expiry_days > 0:
                delta_days = (not_after - datetime.now(timezone.utc)).total_seconds() / 86400
                if delta_days <= expiry_days:
                    events.append(ScanEvent(
                        event_type="ssl_certificate_expiring",
                        value=expiry_str,
                        source_module=self.slug,
                        root_target=ctx.root_target,
                        parent_event_id=parent_event.event_id,
                        confidence=84,
                        visibility=100,
                        risk_score=20,
                        tags=["certspotter", "certificate", "expiring"],
                        raw_payload={"source_domain": parent_event.value},
                    ))

        for host in hosts[:200]:
            evt_type = self._classify_host_event(host, target_domain, verify_names)
            events.append(ScanEvent(
                event_type=evt_type,
                value=host,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=76,
                visibility=100,
                risk_score=5,
                tags=["certspotter", "certificate", "dns_name"],
                raw_payload={"source_domain": parent_event.value},
            ))

            if not self._looks_like_domain(host):
                continue

            domain_evt_type = "domain_name" if evt_type != "co_hosted_site" else "co_hosted_site_domain"
            events.append(ScanEvent(
                event_type=domain_evt_type,
                value=host,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=72,
                visibility=100,
                risk_score=3,
                tags=["certspotter", "certificate", "domain"],
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

    def _classify_host_event(self, host: str, target_domain: str, verify_names: bool) -> str:
        if not self._matches_target(host, target_domain):
            return "co_hosted_site"
        if verify_names and not self._resolves(host):
            return "internet_name_unresolved"
        return "internet_name"

    def _matches_target(self, host: str, target_domain: str) -> bool:
        return host == target_domain or host.endswith("." + target_domain)

    def _resolves(self, host: str) -> bool:
        try:
            socket.getaddrinfo(host, None)
            return True
        except OSError:
            return False

    def _looks_like_domain(self, value: str) -> bool:
        if not value or " " in value or "." not in value:
            return False
        try:
            ipaddress.ip_address(value)
            return False
        except ValueError:
            return True

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
