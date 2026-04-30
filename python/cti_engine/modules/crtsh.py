"""crt.sh certificate transparency module for the first-party CTI engine."""

from __future__ import annotations

import ipaddress
import json
import socket
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
    produced_types = {
        "raw_rir_data",
        "ssl_certificate_raw",
        "internet_name",
        "internet_name_unresolved",
        "domain_name",
        "co_hosted_site",
        "co_hosted_site_domain",
    }
    requires_key = False

    DEFAULT_BASE_URL = "https://crt.sh"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        api_config = ctx.api_config_for(self.slug)
        settings = ctx.module_settings_for(self.slug)
        base_url = str(api_config.get("base_url", "")).strip() or self.DEFAULT_BASE_URL
        timeout = int(ctx.request.settings.global_settings.get("http_timeout", 25) or 25)
        fetch_certs = self._truthy(settings.get("fetchcerts", settings.get("fetch_certs", True)))

        payload = self._fetch_payload(event.value, base_url, timeout, ctx)
        if payload is None:
            return

        certificate_texts: list[str] = []
        if fetch_certs:
            certificate_ids = self._extract_certificate_ids(payload)
            certificate_texts = self._fetch_certificates(certificate_ids, base_url, timeout, ctx)

        for child in self._events_from_payload(payload, certificate_texts, event, settings, ctx):
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
        certificate_texts: list[str],
        parent_event: ScanEvent,
        settings: dict[str, Any],
        ctx,
    ) -> list[ScanEvent]:
        verify_names = self._truthy(settings.get("verify", settings.get("verify_san", True)))
        target_domain = parent_event.value.strip().lower()

        names: list[str] = []
        seen_names: set[str] = set()

        for row in payload:
            candidates = []
            common_name = row.get("common_name")
            if common_name:
                candidates.append(common_name)
            name_value = row.get("name_value")
            if name_value:
                candidates.extend(str(name_value).splitlines())

            for candidate in candidates:
                normalized = self._normalize_dns_name(candidate)
                if not normalized or normalized == target_domain or normalized in seen_names:
                    continue
                seen_names.add(normalized)
                names.append(normalized)

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
                tags=["crt-sh", "raw"],
                raw_payload={"row_count": len(payload)},
            )
        ]

        for cert_text in certificate_texts:
            events.append(ScanEvent(
                event_type="ssl_certificate_raw",
                value=cert_text,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=84,
                visibility=100,
                risk_score=0,
                tags=["crt-sh", "certificate", "raw"],
                raw_payload={"source_domain": parent_event.value},
            ))

        for name in names[:200]:
            evt_type = self._classify_host_event(name, target_domain, verify_names)
            events.append(ScanEvent(
                event_type=evt_type,
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

            if not self._looks_like_domain(name):
                continue

            domain_evt_type = "domain_name" if evt_type != "co_hosted_site" else "co_hosted_site_domain"
            events.append(ScanEvent(
                event_type=domain_evt_type,
                value=name,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=72,
                visibility=100,
                risk_score=3,
                tags=["crt-sh", "certificate", "domain"],
                raw_payload={"source_domain": parent_event.value},
            ))

        return events

    def _extract_certificate_ids(self, payload: list[dict[str, Any]]) -> list[int]:
        ids: list[int] = []
        seen: set[int] = set()
        for row in payload:
            raw_id = row.get("id")
            try:
                cert_id = int(raw_id)
            except (TypeError, ValueError):
                continue
            if cert_id in seen:
                continue
            seen.add(cert_id)
            ids.append(cert_id)
        return ids

    def _fetch_certificates(
        self,
        certificate_ids: list[int],
        base_url: str,
        timeout: int,
        ctx,
    ) -> list[str]:
        texts: list[str] = []
        for cert_id in certificate_ids[:50]:
            cert_text = self._fetch_certificate(cert_id, base_url, timeout, ctx)
            if cert_text:
                texts.append(cert_text)
        return texts

    def _fetch_certificate(self, cert_id: int, base_url: str, timeout: int, ctx) -> str | None:
        endpoint = f"{base_url.rstrip('/')}?{urllib.parse.urlencode({'d': cert_id})}"
        request = urllib.request.Request(
            endpoint,
            headers={"Accept": "*/*", "User-Agent": "CTI Engine"},
            method="GET",
        )

        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec - fixed provider URL
                content = response.read().decode("utf-8", errors="replace").strip()
        except Exception as exc:
            ctx.warning(f"crt.sh certificate fetch failed for id {cert_id}: {exc}", self.slug)
            return None

        return content or None

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
