"""APIVoid module for the first-party CTI engine."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, AsyncIterator

from ..events import ScanEvent
from ..module_base import BaseModule


class ApiVoidModule(BaseModule):
    slug = "apivoid"
    name = "APIVoid"
    watched_types = {"domain", "ip", "url", "email"}
    produced_types = {
        "ip",
        "internet_name",
        "email",
        "linked_url_internal",
        "malicious_domain",
        "malicious_ip",
        "malicious_url",
    }
    requires_key = True

    DEFAULT_BASE_URL = "https://endpoint.apivoid.com"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        api_config = ctx.api_config_for(self.slug)
        api_key = str(api_config.get("api_key", "")).strip()
        if not api_key:
            ctx.error("APIVoid module requires an API key.", self.slug)
            return

        settings = ctx.module_settings_for(self.slug)
        if not self._is_enabled_for_event_type(event.event_type, settings):
            ctx.debug(f"APIVoid checks are disabled for event type '{event.event_type}'.", self.slug)
            return

        base_url = str(api_config.get("base_url", "")).strip() or self.DEFAULT_BASE_URL
        timeout = int(
            settings.get("request_timeout")
            or ctx.request.settings.global_settings.get("http_timeout", 15)
            or 15
        )

        payload = self._fetch_payload(
            event.event_type,
            event.value,
            api_key,
            base_url,
            timeout,
            ctx,
        )
        if payload is None:
            return

        for child in self._events_from_payload(payload, event, ctx, settings):
            yield child

    def _is_enabled_for_event_type(self, event_type: str, settings: dict[str, Any]) -> bool:
        mapping = {
            "ip": "check_ip_reputation",
            "domain": "check_domain_reputation",
            "url": "check_url_reputation",
            "email": "check_email_verify",
        }
        setting_key = mapping.get(event_type)
        if not setting_key:
            return False
        raw = settings.get(setting_key, True)
        return str(raw).strip().lower() not in {"0", "false", "no", "off"}

    def _fetch_payload(
        self,
        event_type: str,
        value: str,
        api_key: str,
        base_url: str,
        timeout: int,
        ctx,
    ) -> dict[str, Any] | None:
        endpoint = self._build_endpoint(base_url, event_type, value, api_key)
        if endpoint is None:
            ctx.debug(f"APIVoid does not yet handle event type '{event_type}'.", self.slug)
            return None

        ctx.info(f"Fetching APIVoid data for {value}.", self.slug)
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
                ctx.info(f"APIVoid has no data for {value}.", self.slug)
                return None
            if exc.code == 429:
                ctx.error("Your request to APIVoid was throttled.", self.slug)
                return None
            if exc.code in (401, 403):
                ctx.error("APIVoid rejected the API key or access token.", self.slug)
                return None
            ctx.warning(f"APIVoid request failed for {value}: HTTP {exc.code}", self.slug)
            return None
        except Exception as exc:
            ctx.warning(f"APIVoid request failed for {value}: {exc}", self.slug)
            return None

        if status >= 400:
            ctx.warning(f"APIVoid returned HTTP {status} for {value}.", self.slug)
            return None

        try:
            decoded = json.loads(content)
        except json.JSONDecodeError as exc:
            ctx.error(f"APIVoid returned invalid JSON: {exc}", self.slug)
            return None

        provider_error = str(decoded.get("error", "") or "").strip()
        if provider_error:
            ctx.warning(f"APIVoid returned an error: {provider_error}", self.slug)
            return None

        return decoded

    def _build_endpoint(self, base_url: str, event_type: str, value: str, api_key: str) -> str | None:
        base = base_url.rstrip("/")
        if event_type == "ip":
            return f"{base}/iprep/v1/pay-as-you-go/?key={urllib.parse.quote(api_key)}&ip={urllib.parse.quote(value)}"
        if event_type == "domain":
            return f"{base}/domainbl/v1/pay-as-you-go/?key={urllib.parse.quote(api_key)}&host={urllib.parse.quote(value)}"
        if event_type == "url":
            return f"{base}/urlrep/v1/pay-as-you-go/?key={urllib.parse.quote(api_key)}&url={urllib.parse.quote(value, safe='')}"
        if event_type == "email":
            return f"{base}/emailverify/v1/pay-as-you-go/?key={urllib.parse.quote(api_key)}&email={urllib.parse.quote(value)}"
        return None

    def _events_from_payload(
        self,
        payload: dict[str, Any],
        parent_event: ScanEvent,
        ctx,
        settings: dict[str, Any],
    ) -> list[ScanEvent]:
        if parent_event.event_type == "ip":
            return self._ip_events(payload, parent_event, ctx, settings)
        if parent_event.event_type == "domain":
            return self._domain_events(payload, parent_event, ctx, settings)
        if parent_event.event_type == "url":
            return self._url_events(payload, parent_event, ctx)
        if parent_event.event_type == "email":
            return self._email_events(payload, parent_event, ctx)
        return []

    def _ip_events(
        self,
        payload: dict[str, Any],
        parent_event: ScanEvent,
        ctx,
        settings: dict[str, Any],
    ) -> list[ScanEvent]:
        report = (((payload.get("data") or {}).get("report")) or {})
        blacklist = report.get("blacklists") or {}
        info = report.get("information") or {}
        anonymity = report.get("anonymity") or {}

        hits, total = self._parse_detection_rate(blacklist.get("detection_rate"))
        min_hits = int(settings.get("min_blacklist_detections", 1) or 1)
        engines_count = int(blacklist.get("engines_count", 0) or 0)

        is_proxy = bool(anonymity.get("is_proxy"))
        is_vpn = bool(anonymity.get("is_vpn"))
        is_tor = bool(anonymity.get("is_tor"))
        reverse_dns = self._normalize_hostname(info.get("reverse_dns"))

        events: list[ScanEvent] = []
        if hits >= min_hits or is_proxy or is_vpn or is_tor:
            tags = ["apivoid", "ip"]
            if hits >= min_hits:
                tags.append("blacklisted")
            if is_proxy:
                tags.append("proxy")
            if is_vpn:
                tags.append("vpn")
            if is_tor:
                tags.append("tor")

            events.append(ScanEvent(
                event_type="malicious_ip",
                value=parent_event.value,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=min(99, 55 + min(39, hits * 10) + (10 if is_proxy or is_vpn or is_tor else 0)),
                visibility=100,
                risk_score=self._risk_from_blacklist_hits(hits, is_proxy, is_vpn, is_tor),
                tags=tags,
                raw_payload={
                    "detection_hits": hits,
                    "detection_total": total,
                    "engines_count": engines_count,
                    "reverse_dns": reverse_dns,
                    "anonymity": {"proxy": is_proxy, "vpn": is_vpn, "tor": is_tor},
                },
            ))

        if reverse_dns and reverse_dns != parent_event.value.strip().lower():
            events.append(ScanEvent(
                event_type="internet_name",
                value=reverse_dns,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=75,
                visibility=100,
                risk_score=10,
                tags=["apivoid", "reverse_dns"],
                raw_payload={"source_ip": parent_event.value},
            ))

        return events

    def _domain_events(
        self,
        payload: dict[str, Any],
        parent_event: ScanEvent,
        ctx,
        settings: dict[str, Any],
    ) -> list[ScanEvent]:
        report = (((payload.get("data") or {}).get("report")) or {})
        blacklist = report.get("blacklists") or {}
        server = report.get("server") or {}

        hits, total = self._parse_detection_rate(blacklist.get("detection_rate"))
        min_hits = int(settings.get("min_blacklist_detections", 1) or 1)
        server_ip = str(server.get("ip", "") or "").strip()

        events: list[ScanEvent] = []
        if hits >= min_hits:
            events.append(ScanEvent(
                event_type="malicious_domain",
                value=parent_event.value,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=min(99, 60 + min(39, hits * 10)),
                visibility=100,
                risk_score=self._risk_from_blacklist_hits(hits),
                tags=["apivoid", "domain", "blacklisted"],
                raw_payload={
                    "detection_hits": hits,
                    "detection_total": total,
                    "server_ip": server_ip,
                    "server_country": server.get("country_name"),
                    "server_isp": server.get("isp"),
                },
            ))

        if server_ip and server_ip != parent_event.value:
            events.append(ScanEvent(
                event_type="ip",
                value=server_ip,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=80,
                visibility=100,
                risk_score=15,
                tags=["apivoid", "server_ip"],
                raw_payload={"source_domain": parent_event.value},
            ))

        return events

    def _url_events(
        self,
        payload: dict[str, Any],
        parent_event: ScanEvent,
        ctx,
    ) -> list[ScanEvent]:
        report = (((payload.get("data") or {}).get("report")) or {})
        raw_risk = report.get("risk_score", {})
        if isinstance(raw_risk, dict):
            risk_score = int(raw_risk.get("result", 0) or 0)
        else:
            risk_score = int(raw_risk or 0)
        suspicious = bool(report.get("is_suspicious"))
        event_type = "malicious_url" if suspicious or risk_score >= 70 else "linked_url_internal"

        events = [ScanEvent(
            event_type=event_type,
            value=parent_event.value,
            source_module=self.slug,
            root_target=ctx.root_target,
            parent_event_id=parent_event.event_id,
            confidence=80 if suspicious or risk_score >= 70 else 70,
            visibility=100,
            risk_score=max(0, min(100, risk_score)),
            tags=["apivoid", "url", "suspicious" if suspicious else "observed"],
            raw_payload={
                "risk_score": risk_score,
                "is_suspicious": suspicious,
                "response_code": ((report.get("response_headers") or {}).get("code")),
                "server": ((report.get("response_headers") or {}).get("server")),
            },
        )]

        host = self._hostname_from_url(parent_event.value)
        if host:
            events.append(ScanEvent(
                event_type="internet_name",
                value=host,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=75,
                visibility=100,
                risk_score=10,
                tags=["apivoid", "url", "hostname"],
                raw_payload={"source_url": parent_event.value},
            ))

        return events

    def _email_events(
        self,
        payload: dict[str, Any],
        parent_event: ScanEvent,
        ctx,
    ) -> list[ScanEvent]:
        data = payload.get("data") or {}
        is_disposable = bool(data.get("is_disposable"))
        is_suspicious = bool(data.get("is_suspicious_domain"))
        is_blacklisted = bool(data.get("is_domain_blacklisted"))
        valid_format = bool(data.get("valid_format"))
        has_mx = bool(data.get("has_mx_records"))
        is_free = bool(data.get("is_free"))

        score = 0
        if is_disposable:
            score += 30
        if is_suspicious:
            score += 40
        if is_blacklisted:
            score += 50
        if not valid_format:
            score = max(score, 25)
        elif not has_mx:
            score = max(score, 20)
        score = min(score, 100)

        tags = ["apivoid", "email"]
        if is_disposable:
            tags.append("disposable")
        if is_suspicious:
            tags.append("suspicious")
        if is_blacklisted:
            tags.append("blacklisted")
        if is_free:
            tags.append("free_provider")

        events = [ScanEvent(
            event_type="email",
            value=parent_event.value,
            source_module=self.slug,
            root_target=ctx.root_target,
            parent_event_id=parent_event.event_id,
            confidence=75,
            visibility=100,
            risk_score=score,
            tags=tags,
            raw_payload={
                "valid_format": valid_format,
                "has_mx_records": has_mx,
                "is_disposable": is_disposable,
                "is_suspicious_domain": is_suspicious,
                "is_domain_blacklisted": is_blacklisted,
                "domain_age_in_days": data.get("domain_age_in_days"),
            },
        )]

        domain = self._domain_from_email(parent_event.value)
        if domain and domain != ctx.root_target:
            events.append(ScanEvent(
                event_type="internet_name",
                value=domain,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=70,
                visibility=100,
                risk_score=10,
                tags=["apivoid", "email", "domain"],
                raw_payload={"source_email": parent_event.value},
            ))

        return events

    def _parse_detection_rate(self, value: Any) -> tuple[int, int]:
        raw = str(value or "").strip()
        if "/" not in raw:
            return 0, 0
        left, right = raw.split("/", 1)
        try:
            return int(left), int(right)
        except ValueError:
            return 0, 0

    def _risk_from_blacklist_hits(
        self,
        hits: int,
        is_proxy: bool = False,
        is_vpn: bool = False,
        is_tor: bool = False,
    ) -> int:
        score = 0
        if hits >= 5:
            score = 90
        elif hits >= 3:
            score = 70
        elif hits >= 1:
            score = 40

        if is_proxy:
            score = max(score, 35)
        if is_vpn:
            score = max(score, 35)
        if is_tor:
            score = max(score, 50)
        return min(score, 100)

    def _hostname_from_url(self, value: str) -> str:
        try:
            parsed = urllib.parse.urlparse(value)
        except Exception:
            return ""
        return self._normalize_hostname(parsed.hostname)

    def _normalize_hostname(self, value: Any) -> str:
        hostname = str(value or "").strip().lower()
        if hostname in {"", "n/a", "na", "unknown"}:
            return ""
        return hostname

    def _domain_from_email(self, value: str) -> str:
        _, sep, domain = str(value or "").partition("@")
        if not sep:
            return ""
        return self._normalize_hostname(domain)
