"""Wave 1 no-key OSINT modules for the first-party CTI engine."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import re
import socket
import urllib.parse
import urllib.request
from typing import Any, AsyncIterator

from ..events import ScanEvent
from ..module_base import BaseModule
from ..targets import DOMAIN_RX, EMAIL_RX
from .no_key_reputation import (
    USER_AGENT,
    _cti_slug,
    _emit_malicious_and_blacklisted,
    _fetch_text,
    _host_resolves,
    _hostname,
    _http_timeout,
    _make_event,
    _matches_root_target,
    _module_bool,
    _module_int,
    _module_setting,
    _valid_ip,
)


def _fetch_json(url: str, timeout: int, ctx, slug: str) -> Any | None:
    content = _fetch_text(url, timeout, ctx, slug, accept="application/json, text/plain, */*")
    if content is None:
        return None
    try:
        return json.loads(content)
    except json.JSONDecodeError as exc:
        ctx.warning(f"{slug} returned invalid JSON: {exc}", slug)
        return None


def _parse_ndjson(content: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in content.splitlines():
        candidate = line.strip()
        if not candidate:
            continue
        try:
            decoded = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(decoded, dict):
            rows.append(decoded)
    return rows


def _normalize_host(value: str) -> str:
    host = _hostname(value)
    if host:
        return host
    return str(value or "").strip().lower().rstrip(".")


def _root_host(ctx, event: ScanEvent) -> str:
    root = _normalize_host(ctx.root_target)
    if root:
        return root
    return _normalize_host(event.value)


def _event_value(label: str, indicator: str, source_url: str) -> str:
    return f"{label} [{indicator}]\n<SFURL>{source_url}</SFURL>"


def _extract_subdomain_rows(body: str) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for line in body.splitlines():
        candidate = line.strip()
        if not candidate or candidate.lower().startswith("error"):
            continue
        parts = [part.strip() for part in candidate.split(",", 1)]
        if len(parts) != 2:
            continue
        host, ip_value = parts
        if not host:
            continue
        rows.append((host.lower().rstrip("."), ip_value))
    return rows


def _dns_resolves(host: str) -> bool:
    try:
        return bool(socket.getaddrinfo(host, None))
    except OSError:
        return False


def _host_maps_to_ip(host: str, ip_value: str) -> bool:
    candidate_ip = str(ip_value or "").strip()
    if not host or not candidate_ip:
        return False
    try:
        for info in socket.getaddrinfo(host, None):
            sockaddr = info[4]
            if isinstance(sockaddr, tuple) and sockaddr and str(sockaddr[0]).strip() == candidate_ip:
                return True
    except OSError:
        return False
    return False


def _timestamp_ms_is_too_old(last_seen: Any, max_age_days: int) -> bool:
    if max_age_days <= 0:
        return False
    try:
        timestamp = int(last_seen)
    except Exception:
        return True
    cutoff = int(datetime.now(timezone.utc).timestamp() * 1000) - (86400000 * max_age_days)
    return timestamp < cutoff


class CommonCrawlModule(BaseModule):
    slug = "commoncrawl"
    name = "CommonCrawl"
    watched_types = {"domain", "internet_name", "url"}
    produced_types = {"linked_url_internal"}
    requires_key = False

    INDEX_LIST_URL = "https://index.commoncrawl.org/"
    INDEX_URL = "https://index.commoncrawl.org/{index}-index?url={query}&output=json"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        timeout = _http_timeout(ctx)
        indexes = self._fetch_indexes(timeout, ctx)
        if not indexes:
            return

        max_indexes = _module_int(ctx, self.slug, _cti_slug(self.slug), ("max_indexes", "indexes"), 6)
        query = self._query_for_event(event)
        for index_name in indexes[: max(1, max_indexes)]:
            endpoint = self.INDEX_URL.format(
                index=urllib.parse.quote(index_name, safe="-"),
                query=urllib.parse.quote(query, safe="*:/?&=%"),
            )
            payload = _fetch_text(endpoint, timeout, ctx, self.slug, accept="application/json, text/plain, */*")
            if not payload:
                continue
            for child in self._events_from_records(_parse_ndjson(payload), event, ctx):
                yield child

    def _fetch_indexes(self, timeout: int, ctx) -> list[str]:
        payload = _fetch_text(self.INDEX_LIST_URL, timeout, ctx, self.slug, accept="application/json, text/html, text/plain, */*")
        if not payload:
            return []
        indexes = re.findall(r"(CC-MAIN-\d+-\d+)", payload)
        indexes.sort(reverse=True)
        unique_indexes: list[str] = []
        seen: set[str] = set()
        for identifier in indexes:
            if identifier in seen:
                continue
            seen.add(identifier)
            unique_indexes.append(identifier)
        return unique_indexes

    def _query_for_event(self, event: ScanEvent) -> str:
        if event.event_type == "url":
            return event.value.rstrip("/") + "/*"
        return f"{event.value.rstrip('/')}/*"

    def _events_from_records(self, records: list[dict[str, Any]], parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        events: list[ScanEvent] = []
        seen: set[str] = set()
        root = _root_host(ctx, parent_event)
        replacement_host = _normalize_host(parent_event.value)
        for record in records:
            url_value = str(record.get("url", "") or "").strip()
            if not url_value or url_value in seen:
                continue
            if replacement_host:
                url_value = url_value.replace(replacement_host + ".", replacement_host)
            host = _normalize_host(url_value)
            if not host:
                continue
            if parent_event.event_type == "url":
                if host != _normalize_host(parent_event.value):
                    continue
            elif not _matches_root_target(host, root):
                continue
            seen.add(url_value)
            events.append(_make_event(
                event_type="linked_url_internal",
                value=url_value,
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=5,
                confidence=75,
                tags=["commoncrawl", "crawl", "url"],
                raw_payload={"record": record, "spiderfoot_parity": True},
            ))
        return events


class ArchiveOrgModule(BaseModule):
    slug = "archive-org"
    name = "Archive.org"
    watched_types = {
        "domain",
        "url",
        "interesting_file",
        "url_password",
        "url_form",
        "url_flash",
        "url_static",
        "url_java_applet",
        "url_upload",
        "url_javascript",
        "url_web_framework",
    }
    produced_types = {
        "historic_url",
        "interesting_file_historic",
        "url_password_historic",
        "url_form_historic",
        "url_flash_historic",
        "url_static_historic",
        "url_java_applet_historic",
        "url_upload_historic",
        "url_javascript_historic",
        "url_web_framework_historic",
    }
    requires_key = False

    SNAPSHOT_URL = "https://archive.org/wayback/available?url={url}&timestamp={timestamp}"
    HISTORIC_MAP = {
        "interesting_file": "interesting_file_historic",
        "url_password": "url_password_historic",
        "url_form": "url_form_historic",
        "url_flash": "url_flash_historic",
        "url_static": "url_static_historic",
        "url_java_applet": "url_java_applet_historic",
        "url_upload": "url_upload_historic",
        "url_javascript": "url_javascript_historic",
        "url_web_framework": "url_web_framework_historic",
    }

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        if not self._event_enabled(event, ctx):
            return
        timeout = _http_timeout(ctx)
        seen_urls: set[str] = set()
        for timestamp in self._timestamps(ctx):
            endpoint = self.SNAPSHOT_URL.format(
                url=urllib.parse.quote(event.value, safe=":/?&=%"),
                timestamp=timestamp,
            )
            payload = _fetch_json(endpoint, timeout, ctx, self.slug)
            if payload is None:
                continue
            for child in self._events_from_snapshot(payload, event, ctx):
                if child.value in seen_urls:
                    continue
                seen_urls.add(child.value)
                yield child

    def _timestamps(self, ctx) -> list[str]:
        raw_days = str(_module_setting(ctx, self.slug, _cti_slug(self.slug), ("farback", "days_back"), "30,60,90") or "30,60,90")
        days: list[int] = []
        for item in raw_days.split(","):
            try:
                days.append(max(0, int(item.strip())))
            except ValueError:
                continue
        if not days:
            days = [30, 60, 90]
        now = datetime.now(timezone.utc)
        return [(now - timedelta(days=day)).strftime("%Y%m%d") for day in days]

    def _event_enabled(self, event: ScanEvent, ctx) -> bool:
        option_map = {
            "interesting_file": "intfiles",
            "url_password": "passwordpages",
            "url_form": "formpages",
            "url_flash": "flashpages",
            "url_java_applet": "javapages",
            "url_static": "staticpages",
            "url_upload": "uploadpages",
            "url_web_framework": "webframeworkpages",
            "url_javascript": "javascriptpages",
        }
        option_key = option_map.get(event.event_type)
        if not option_key:
            return True
        default_map = {
            "intfiles": True,
            "passwordpages": True,
            "formpages": False,
            "flashpages": False,
            "javapages": False,
            "staticpages": False,
            "uploadpages": False,
            "webframeworkpages": False,
            "javascriptpages": False,
        }
        return _module_bool(ctx, self.slug, _cti_slug(self.slug), option_key, default_map.get(option_key, False))

    def _events_from_snapshot(self, payload: dict[str, Any], parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        snapshots = payload.get("archived_snapshots")
        if not isinstance(snapshots, dict):
            return []
        closest = snapshots.get("closest")
        if not isinstance(closest, dict) or not closest.get("available"):
            return []

        archive_url = str(closest.get("url", "") or "").strip()
        if not archive_url:
            return []
        event_type = self.HISTORIC_MAP.get(parent_event.event_type, "historic_url")
        return [_make_event(
            event_type=event_type,
            value=archive_url,
            slug=self.slug,
            parent_event=parent_event,
            ctx=ctx,
            risk_score=0,
            confidence=85,
            tags=["archive-org", "historic", parent_event.event_type],
            raw_payload={"snapshot": closest, "spiderfoot_parity": True},
        )]


class CrobatModule(BaseModule):
    slug = "crobat"
    name = "Crobat"
    watched_types = {"domain", "internet_name"}
    produced_types = {"raw_rir_data", "internet_name", "internet_name_unresolved"}
    requires_key = False

    BASE_URL = "https://sonar.omnisint.io/subdomains/{domain}"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        timeout = _http_timeout(ctx)
        max_pages = _module_int(ctx, self.slug, _cti_slug(self.slug), "max_pages", 10)
        for page in range(max(1, max_pages)):
            endpoint = self.BASE_URL.format(domain=urllib.parse.quote(event.value, safe=""))
            if page > 0:
                endpoint += f"?page={page}"
            payload = _fetch_json(endpoint, timeout, ctx, self.slug)
            if payload in (None, "null", []):
                break
            page_events = self._events_from_page_payload(payload, event, ctx)
            if not page_events:
                break
            for child in page_events:
                yield child

    def _events_from_page_payload(self, payload: Any, parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        if not isinstance(payload, list):
            return []
        events: list[ScanEvent] = []
        root = _root_host(ctx, parent_event)
        verify = _module_bool(ctx, self.slug, _cti_slug(self.slug), ("verify", "dns_resolve"), True)
        events.append(_make_event(
            event_type="raw_rir_data",
            value=str(payload),
            slug=self.slug,
            parent_event=parent_event,
            ctx=ctx,
            risk_score=0,
            confidence=70,
            tags=["crobat", "raw"],
            raw_payload={"rows": payload[:50], "spiderfoot_parity": True},
        ))

        seen: set[str] = set()
        for row in payload:
            candidate = str(row or "").strip().lower().rstrip(".")
            if not candidate or candidate in seen:
                continue
            if not _matches_root_target(candidate, root):
                continue
            seen.add(candidate)
            event_type = "internet_name"
            if verify and not _host_resolves(candidate):
                event_type = "internet_name_unresolved"
            events.append(_make_event(
                event_type=event_type,
                value=candidate,
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=5,
                confidence=80,
                tags=["crobat", "subdomain"],
                raw_payload={"subdomain": candidate, "spiderfoot_parity": True},
            ))
        return events


class HackerTargetModule(BaseModule):
    slug = "hackertarget"
    name = "HackerTarget"
    watched_types = {"domain", "internet_name", "ip"}
    produced_types = {"raw_dns_records", "raw_rir_data", "internet_name", "ip", "co_hosted_site", "co_hosted_site_domain"}
    requires_key = False

    HOSTSEARCH_URL = "https://api.hackertarget.com/hostsearch/?q={query}"
    REVERSE_IP_URL = "https://api.hackertarget.com/reverseiplookup/?q={query}"
    ASLOOKUP_URL = "https://api.hackertarget.com/aslookup/?q={query}"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        timeout = _http_timeout(ctx)
        if event.event_type in {"domain", "internet_name"}:
            endpoint = self.HOSTSEARCH_URL.format(query=urllib.parse.quote(event.value, safe=""))
            payload = _fetch_text(endpoint, timeout, ctx, self.slug, accept="text/plain, */*")
            if not payload:
                return
            for child in self._events_from_hostsearch(payload, event, ctx):
                yield child
            return

        endpoint = self.REVERSE_IP_URL.format(query=urllib.parse.quote(event.value, safe=""))
        payload = _fetch_text(endpoint, timeout, ctx, self.slug, accept="text/plain, */*")
        if payload:
            for child in self._events_from_reverse_ip(payload, event, ctx):
                yield child
        aslookup = _fetch_text(
            self.ASLOOKUP_URL.format(query=urllib.parse.quote(event.value, safe="")),
            timeout,
            ctx,
            self.slug,
            accept="text/plain, */*",
        )
        if aslookup:
            yield _make_event(
                event_type="raw_rir_data",
                value=f"HackerTarget ASN data for {event.value}",
                slug=self.slug,
                parent_event=event,
                ctx=ctx,
                risk_score=0,
                confidence=70,
                tags=["hackertarget", "asn"],
                raw_payload={"body": aslookup, "spiderfoot_parity": True},
            )

    def _events_from_hostsearch(self, body: str, parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        rows = _extract_subdomain_rows(body)
        if not rows:
            return []
        events: list[ScanEvent] = [_make_event(
            event_type="raw_dns_records",
            value=f"HackerTarget hostsearch results for {parent_event.value}",
            slug=self.slug,
            parent_event=parent_event,
            ctx=ctx,
            risk_score=0,
            confidence=70,
            tags=["hackertarget", "dns"],
            raw_payload={"rows": rows[:50], "spiderfoot_parity": True},
        )]
        root = _root_host(ctx, parent_event)
        seen_hosts: set[str] = set()
        seen_ips: set[str] = set()
        for host, ip_value in rows:
            if _matches_root_target(host, root) and host not in seen_hosts:
                seen_hosts.add(host)
                events.append(_make_event(
                    event_type="internet_name",
                    value=host,
                    slug=self.slug,
                    parent_event=parent_event,
                    ctx=ctx,
                    risk_score=5,
                    confidence=80,
                    tags=["hackertarget", "subdomain"],
                    raw_payload={"ip": ip_value, "spiderfoot_parity": True},
                ))
            if ip_value and _valid_ip(ip_value) and ip_value not in seen_ips:
                seen_ips.add(ip_value)
                events.append(_make_event(
                    event_type="ip",
                    value=ip_value,
                    slug=self.slug,
                    parent_event=parent_event,
                    ctx=ctx,
                    risk_score=5,
                    confidence=80,
                    tags=["hackertarget", "dns"],
                    raw_payload={"hostname": host, "spiderfoot_parity": True},
                ))
        return events

    def _events_from_reverse_ip(self, body: str, parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        events: list[ScanEvent] = []
        seen: set[str] = set()
        verify = _module_bool(ctx, self.slug, _cti_slug(self.slug), "verify", True)
        include_same_domain = _module_bool(ctx, self.slug, _cti_slug(self.slug), "cohostsamedomain", False)
        max_cohosts = _module_int(ctx, self.slug, _cti_slug(self.slug), "maxcohost", 100)
        cohost_count = 0
        for line in body.splitlines():
            host = str(line or "").strip().lower().rstrip(".")
            if not host or host in seen or "." not in host:
                continue
            if not include_same_domain and _matches_root_target(host, _root_host(ctx, parent_event)):
                continue
            if verify and not _host_maps_to_ip(host, parent_event.value):
                continue
            if cohost_count >= max_cohosts:
                break
            seen.add(host)
            events.append(_make_event(
                event_type="co_hosted_site",
                value=host,
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=15,
                confidence=75,
                tags=["hackertarget", "cohost"],
                raw_payload={"spiderfoot_parity": True},
            ))
            cohost_count += 1
        return events


class IscSansModule(BaseModule):
    slug = "isc-sans"
    name = "Internet Storm Center"
    watched_types = {"ip", "ipv6", "affiliate_ipaddr", "affiliate_ipv6"}
    produced_types = {"malicious_ip", "blacklisted_ip", "malicious_affiliate_ipaddr", "blacklisted_affiliate_ipaddr"}
    requires_key = False

    API_URL = "https://isc.sans.edu/api/ip/{query}?json"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        if event.event_type.startswith("affiliate_") and not _module_bool(
            ctx,
            self.slug,
            _cti_slug(self.slug),
            "checkaffiliates",
            True,
        ):
            return
        timeout = _http_timeout(ctx)
        endpoint = self.API_URL.format(query=urllib.parse.quote(event.value, safe=""))
        payload = _fetch_json(endpoint, timeout, ctx, self.slug)
        if not isinstance(payload, dict):
            return
        for child in self._events_from_payload(payload, event, ctx):
            yield child

    def _events_from_payload(self, payload: dict[str, Any], parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        candidate = payload.get("ip") if isinstance(payload.get("ip"), dict) else payload
        if not isinstance(candidate, dict):
            return []
        try:
            attacks_raw = candidate.get("attacks")
            reports_raw = candidate.get("count")
            attacks = int(attacks_raw or 0)
            reports = int(reports_raw or 0)
        except Exception:
            attacks_raw = None
            reports_raw = None
            attacks = 0
            reports = 0
        if attacks_raw in (None, "") and reports_raw in (None, ""):
            return []

        label = _event_value("Internet Storm Center", parent_event.value, f"https://isc.sans.edu/api/ip/{parent_event.value}")
        event_types = (
            ("malicious_affiliate_ipaddr", "blacklisted_affiliate_ipaddr")
            if parent_event.event_type.startswith("affiliate_")
            else ("malicious_ip", "blacklisted_ip")
        )
        raw = {"attacks": attacks, "reports": reports, "payload": candidate, "spiderfoot_parity": True}
        return [
            _make_event(
                event_type=event_types[0],
                value=label,
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=75,
                confidence=88,
                tags=["isc-sans", "malicious"],
                raw_payload=raw,
            ),
            _make_event(
                event_type=event_types[1],
                value=label,
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=70,
                confidence=88,
                tags=["isc-sans", "blacklist"],
                raw_payload=raw,
            ),
        ]


class MnemonicPdnsModule(BaseModule):
    slug = "mnemonic-pdns"
    name = "Mnemonic PassiveDNS"
    watched_types = {"domain", "internet_name", "ip", "ipv6"}
    produced_types = {"raw_dns_records", "ip", "ipv6", "internet_name", "co_hosted_site", "co_hosted_site_domain"}
    requires_key = False

    API_URL = "https://api.mnemonic.no/pdns/v3/{query}?limit={limit}&offset={offset}"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        timeout = _module_int(ctx, self.slug, _cti_slug(self.slug), "timeout", _http_timeout(ctx))
        per_page = _module_int(ctx, self.slug, _cti_slug(self.slug), "per_page", 500)
        max_pages = _module_int(ctx, self.slug, _cti_slug(self.slug), "max_pages", 2)
        rows: list[dict[str, Any]] = []
        for page in range(max(1, max_pages)):
            endpoint = self.API_URL.format(
                query=urllib.parse.quote(event.value, safe=""),
                limit=max(1, per_page),
                offset=page * max(1, per_page),
            )
            payload = _fetch_json(endpoint, timeout, ctx, self.slug)
            if not isinstance(payload, dict):
                break
            response_code = payload.get("responseCode")
            if response_code == 402:
                ctx.warning("mnemonic-pdns resource limit exceeded.", self.slug)
                break
            if response_code not in (None, 200):
                break
            page_rows = payload.get("data")
            if not isinstance(page_rows, list) or not page_rows:
                break
            rows.extend(page_rows)
            size = int(payload.get("size", len(page_rows)) or len(page_rows))
            count = int(payload.get("count", len(page_rows)) or len(page_rows))
            if size < per_page or ((page + 1) * per_page) >= count:
                break
        if not rows:
            return
        for child in self._events_from_records(rows, event, ctx):
            yield child

    def _events_from_records(self, rows: list[dict[str, Any]], parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        events: list[ScanEvent] = []
        root = _root_host(ctx, parent_event)
        verify = _module_bool(ctx, self.slug, _cti_slug(self.slug), "verify", True)
        max_age_days = _module_int(ctx, self.slug, _cti_slug(self.slug), "maxage", 180)
        cohosts_same_domain = _module_bool(ctx, self.slug, _cti_slug(self.slug), "cohostsamedomain", False)
        max_cohosts = _module_int(ctx, self.slug, _cti_slug(self.slug), "maxcohost", 100)
        seen: set[tuple[str, str]] = set()
        cohost_count = 0
        for row in rows[: max(1, len(rows))]:
            if not isinstance(row, dict):
                continue
            rrtype = str(row.get("rrtype", "") or "").strip().upper()
            query = str(row.get("query", "") or "").strip().lower().rstrip(".")
            answer = str(row.get("answer", "") or "").strip().rstrip(".")
            if _timestamp_ms_is_too_old(row.get("lastSeenTimestamp"), max_age_days):
                continue
            if not answer:
                continue

            if parent_event.event_type in {"ip", "ipv6"}:
                if rrtype == "A" and _valid_ip(query):
                    key = ("host", query)
                    if key in seen:
                        continue
                    seen.add(key)
                    if cohosts_same_domain:
                        if cohost_count >= max_cohosts:
                            continue
                        events.append(_make_event(
                            event_type="co_hosted_site",
                            value=query,
                            slug=self.slug,
                            parent_event=parent_event,
                            ctx=ctx,
                            risk_score=10,
                            confidence=78,
                            tags=["mnemonic-pdns", "cohost"],
                            raw_payload={"row": row, "spiderfoot_parity": True},
                        ))
                        cohost_count += 1
                    elif _matches_root_target(query, root):
                        event_type = "internet_name"
                        if verify and not _host_maps_to_ip(query, parent_event.value):
                            event_type = "internet_name_unresolved"
                        events.append(_make_event(
                            event_type=event_type,
                            value=query,
                            slug=self.slug,
                            parent_event=parent_event,
                            ctx=ctx,
                            risk_score=5,
                            confidence=80,
                            tags=["mnemonic-pdns", "host"],
                            raw_payload={"row": row, "spiderfoot_parity": True},
                        ))
                        if DOMAIN_RX.match(query):
                            events.append(_make_event(
                                event_type="domain_name",
                                value=query,
                                slug=self.slug,
                                parent_event=parent_event,
                                ctx=ctx,
                                risk_score=5,
                                confidence=80,
                                tags=["mnemonic-pdns", "domain"],
                                raw_payload={"row": row, "spiderfoot_parity": True},
                            ))
                continue

            if rrtype == "PTR":
                continue
            if rrtype == "CNAME":
                if not _matches_root_target(query, root):
                    continue
                candidate_host = query
            else:
                candidate_host = ""

            if verify:
                if not candidate_host:
                    continue
            else:
                if rrtype == "A" and _valid_ip(answer):
                    key = ("ip", answer)
                    if key not in seen:
                        seen.add(key)
                        events.append(_make_event(
                            event_type="ip",
                            value=answer,
                            slug=self.slug,
                            parent_event=parent_event,
                            ctx=ctx,
                            risk_score=5,
                            confidence=80,
                            tags=["mnemonic-pdns", "answer"],
                            raw_payload={"row": row, "spiderfoot_parity": True},
                        ))
                    continue
                if rrtype == "AAAA" and _valid_ip(answer):
                    key = ("ipv6", answer)
                    if key not in seen:
                        seen.add(key)
                        events.append(_make_event(
                            event_type="ipv6",
                            value=answer,
                            slug=self.slug,
                            parent_event=parent_event,
                            ctx=ctx,
                            risk_score=5,
                            confidence=80,
                            tags=["mnemonic-pdns", "answer"],
                            raw_payload={"row": row, "spiderfoot_parity": True},
                        ))
                    continue
                if not candidate_host:
                    continue

            host_value = candidate_host.lower()
            key = ("internet_name", host_value)
            if key in seen:
                continue
            seen.add(key)
            event_type = "internet_name"
            if verify and not _host_resolves(host_value):
                event_type = "internet_name_unresolved"
            events.append(_make_event(
                event_type=event_type,
                value=host_value,
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=5,
                confidence=78,
                tags=["mnemonic-pdns", "host"],
                raw_payload={"row": row, "spiderfoot_parity": True},
            ))
            if DOMAIN_RX.match(host_value):
                events.append(_make_event(
                    event_type="domain_name",
                    value=host_value,
                    slug=self.slug,
                    parent_event=parent_event,
                    ctx=ctx,
                    risk_score=5,
                    confidence=78,
                    tags=["mnemonic-pdns", "domain"],
                    raw_payload={"row": row, "spiderfoot_parity": True},
                ))
        return events


class PhishStatsModule(BaseModule):
    slug = "phishstats"
    name = "PhishStats"
    watched_types = {"domain", "internet_name", "url", "ip"}
    produced_types = {
        "raw_rir_data",
        "malicious_internet_name",
        "blacklisted_internet_name",
        "malicious_ip",
        "blacklisted_ip",
        "malicious_url",
    }
    requires_key = False

    API_URL = "https://phishstats.info:2096/api/phishing?_where={where}&_sort=-date&_size=25"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        timeout = _http_timeout(ctx)
        where = self._where_clause(event)
        endpoint = self.API_URL.format(where=urllib.parse.quote(where, safe="(),~"))
        payload = _fetch_json(endpoint, timeout, ctx, self.slug)
        if not isinstance(payload, list):
            return
        for child in self._events_from_payload(payload, event, ctx):
            yield child

    def _where_clause(self, event: ScanEvent) -> str:
        if event.event_type == "ip":
            return f"(ip,eq,{event.value})"
        return f"(url,like,~{event.value}~)"

    def _events_from_payload(self, rows: list[dict[str, Any]], parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        events: list[ScanEvent] = []
        indicator = str(parent_event.value or "").strip().lower()
        host_indicator = _normalize_host(parent_event.value)
        for row in rows[:25]:
            if not isinstance(row, dict):
                continue
            url_value = str(row.get("url", "") or "").strip()
            ip_value = str(row.get("ip", "") or "").strip()
            matched = False
            if parent_event.event_type == "ip" and ip_value == parent_event.value:
                matched = True
            elif url_value and indicator and indicator in url_value.lower():
                matched = True
            elif host_indicator and _normalize_host(url_value) == host_indicator:
                matched = True
            if not matched:
                continue
            events.append(_make_event(
                event_type="raw_rir_data",
                value=str(row),
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=0,
                confidence=75,
                tags=["phishstats", "phishing"],
                raw_payload={"row": row, "spiderfoot_parity": True},
            ))
            if parent_event.event_type == "ip":
                events.extend(_emit_malicious_and_blacklisted(
                    parent_event=parent_event,
                    ctx=ctx,
                    slug=self.slug,
                    value=f"PhishStats [{parent_event.value}]",
                    source_url="https://phishstats.info/",
                    tags=["phishstats", "phishing"],
                    risk_score=90,
                    confidence=90,
                ))
            elif parent_event.event_type in {"domain", "internet_name"}:
                events.extend(_emit_malicious_and_blacklisted(
                    parent_event=parent_event,
                    ctx=ctx,
                    slug=self.slug,
                    value=f"PhishStats [{parent_event.value}]",
                    source_url="https://phishstats.info/",
                    tags=["phishstats", "phishing"],
                    risk_score=90,
                    confidence=90,
                ))
            if url_value:
                events.append(_make_event(
                    event_type="malicious_url",
                    value=url_value,
                    slug=self.slug,
                    parent_event=parent_event,
                    ctx=ctx,
                    risk_score=92,
                    confidence=90,
                    tags=["phishstats", "phishing", "malicious"],
                    raw_payload={"row": row, "spiderfoot_parity": True},
                ))
        return events


class RobtexModule(BaseModule):
    slug = "robtex"
    name = "Robtex"
    watched_types = {"domain", "internet_name", "ip"}
    produced_types = {"raw_rir_data", "raw_dns_records", "ip", "ipv6", "co_hosted_site", "co_hosted_site_domain"}
    requires_key = False

    IP_URL = "https://freeapi.robtex.com/ipquery/{query}"
    DOMAIN_URL = "https://freeapi.robtex.com/pdns/forward/{query}"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        timeout = _http_timeout(ctx)
        if event.event_type == "ip":
            endpoint = self.IP_URL.format(query=urllib.parse.quote(event.value, safe=""))
            payload = _fetch_json(endpoint, timeout, ctx, self.slug)
            if not isinstance(payload, dict):
                return
            for child in self._events_from_ip_payload(payload, event, ctx):
                yield child
            return

        endpoint = self.DOMAIN_URL.format(query=urllib.parse.quote(event.value, safe=""))
        payload = _fetch_text(endpoint, timeout, ctx, self.slug, accept="application/json, text/plain, */*")
        if not payload:
            return
        for child in self._events_from_domain_records(_parse_ndjson(payload), event, ctx):
            yield child

    def _events_from_ip_payload(self, payload: dict[str, Any], parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        events: list[ScanEvent] = [_make_event(
            event_type="raw_rir_data",
            value=f"Robtex IP record for {parent_event.value}",
            slug=self.slug,
            parent_event=parent_event,
            ctx=ctx,
            risk_score=0,
            confidence=75,
            tags=["robtex", "raw"],
            raw_payload={"payload": payload, "spiderfoot_parity": True},
        )]
        seen: set[str] = set()
        verify = _module_bool(ctx, self.slug, _cti_slug(self.slug), "verify", True)
        include_same_domain = _module_bool(ctx, self.slug, _cti_slug(self.slug), "cohostsamedomain", False)
        max_cohosts = _module_int(ctx, self.slug, _cti_slug(self.slug), "maxcohost", 100)
        cohost_count = 0
        for row in payload.get("pas", []) or []:
            if not isinstance(row, dict):
                continue
            host = str(row.get("o", "") or "").strip().lower().rstrip(".")
            if not host or host in seen:
                continue
            if not include_same_domain and _matches_root_target(host, _root_host(ctx, parent_event)):
                continue
            if verify and not _host_maps_to_ip(host, parent_event.value):
                continue
            if cohost_count >= max_cohosts:
                break
            seen.add(host)
            events.append(_make_event(
                event_type="co_hosted_site",
                value=host,
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=15,
                confidence=78,
                tags=["robtex", "cohost"],
                raw_payload={"row": row, "spiderfoot_parity": True},
            ))
            cohost_count += 1
        return events

    def _events_from_domain_records(self, rows: list[dict[str, Any]], parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        events: list[ScanEvent] = []
        seen: set[tuple[str, str]] = set()
        for row in rows[:50]:
            rrdata = str(row.get("rrdata", "") or "").strip().rstrip(".")
            rrtype = str(row.get("rrtype", "A") or "A").strip().upper()
            if not rrdata:
                continue
            events.append(_make_event(
                event_type="raw_dns_records",
                value=f"{rrtype} {parent_event.value} -> {rrdata}",
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=0,
                confidence=72,
                tags=["robtex", "dns"],
                raw_payload={"row": row, "spiderfoot_parity": True},
            ))
            if not _valid_ip(rrdata):
                continue
            event_type = "ipv6" if ":" in rrdata else "ip"
            key = (event_type, rrdata)
            if key in seen:
                continue
            seen.add(key)
            events.append(_make_event(
                event_type=event_type,
                value=rrdata,
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=5,
                confidence=80,
                tags=["robtex", "passive-dns"],
                raw_payload={"row": row, "spiderfoot_parity": True},
            ))
        return events


class ThreatCrowdModule(BaseModule):
    slug = "threatcrowd"
    name = "ThreatCrowd"
    watched_types = {"domain", "internet_name", "ip", "email", "hash"}
    produced_types = {
        "raw_rir_data",
        "malicious_internet_name",
        "blacklisted_internet_name",
        "malicious_ip",
        "blacklisted_ip",
        "malicious_email_address",
        "malicious_hash",
        "blacklisted_hash",
        "internet_name",
        "ip",
        "email",
    }
    requires_key = False

    API_BASE = "https://www.threatcrowd.org/searchApi/v2"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        timeout = _http_timeout(ctx)
        endpoint = self._endpoint_for_event(event)
        if not endpoint:
            return
        payload = _fetch_json(endpoint, timeout, ctx, self.slug)
        if not isinstance(payload, dict):
            return
        for child in self._events_from_payload(payload, event, ctx):
            yield child

    def _endpoint_for_event(self, event: ScanEvent) -> str | None:
        if event.event_type == "ip":
            return f"{self.API_BASE}/ip/report/?ip={urllib.parse.quote(event.value, safe='')}"
        if event.event_type in {"domain", "internet_name"}:
            return f"{self.API_BASE}/domain/report/?domain={urllib.parse.quote(event.value, safe='')}"
        if event.event_type == "email":
            return f"{self.API_BASE}/email/report/?email={urllib.parse.quote(event.value, safe='')}"
        if event.event_type == "hash":
            return f"{self.API_BASE}/file/report/?resource={urllib.parse.quote(event.value, safe='')}"
        return None

    def _events_from_payload(self, payload: dict[str, Any], parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        events: list[ScanEvent] = []

        try:
            votes = int(payload.get("votes", 0) or 0)
        except Exception:
            votes = 0
        if votes < 0:
            label = _event_value("ThreatCrowd", parent_event.value, str(payload.get("permalink", "") or "https://www.threatcrowd.org/"))
            if parent_event.event_type == "email":
                events.append(_make_event(
                    event_type="malicious_email_address",
                    value=label,
                    slug=self.slug,
                    parent_event=parent_event,
                    ctx=ctx,
                    risk_score=88,
                    confidence=88,
                    tags=["threatcrowd", "malicious"],
                    raw_payload={"payload": payload, "spiderfoot_parity": True},
                ))
            else:
                events.extend(_emit_malicious_and_blacklisted(
                    parent_event=parent_event,
                    ctx=ctx,
                    slug=self.slug,
                    value=label,
                    source_url=str(payload.get("permalink", "") or "https://www.threatcrowd.org/"),
                    tags=["threatcrowd"],
                    risk_score=88,
                    confidence=88,
                ))
        return events


class MaltiverseModule(BaseModule):
    slug = "maltiverse"
    name = "Maltiverse"
    watched_types = {"domain", "internet_name", "ip", "url", "hash"}
    produced_types = {
        "raw_rir_data",
        "malicious_internet_name",
        "blacklisted_internet_name",
        "malicious_ip",
        "blacklisted_ip",
        "malicious_hash",
        "blacklisted_hash",
        "malicious_url",
        "blacklisted_url",
    }
    requires_key = False

    API_BASE = "https://api.maltiverse.com"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        timeout = _http_timeout(ctx)
        endpoint = self._endpoint_for_event(event)
        if not endpoint:
            return
        payload = self._fetch_payload(endpoint, timeout, ctx)
        if not isinstance(payload, dict):
            return
        for child in self._events_from_payload(payload, event, ctx):
            yield child

    def _endpoint_for_event(self, event: ScanEvent) -> str | None:
        if event.event_type == "ip":
            return f"{self.API_BASE}/ip/{urllib.parse.quote(event.value, safe='')}"
        if event.event_type in {"domain", "internet_name"}:
            return f"{self.API_BASE}/hostname/{urllib.parse.quote(event.value, safe='')}"
        if event.event_type == "hash":
            return f"{self.API_BASE}/sample/{urllib.parse.quote(event.value, safe='')}"
        if event.event_type == "url":
            return f"{self.API_BASE}/url/{urllib.parse.quote(event.value, safe='')}"
        return None

    def _fetch_payload(self, endpoint: str, timeout: int, ctx) -> Any | None:
        request = urllib.request.Request(
            endpoint,
            headers={"Accept": "application/json", "User-Agent": USER_AGENT},
            method="GET",
        )
        ctx.info(f"Fetching {endpoint}.", self.slug)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec - fixed provider URL
                status = int(getattr(response, "status", 200) or 200)
                content = response.read().decode("utf-8", errors="replace")
        except Exception as exc:
            ctx.warning(f"{self.slug} request failed: {exc}", self.slug)
            return None
        if status != 200:
            ctx.warning(f"{self.slug} returned HTTP {status}.", self.slug)
            return None
        try:
            return json.loads(content)
        except json.JSONDecodeError as exc:
            ctx.warning(f"{self.slug} returned invalid JSON: {exc}", self.slug)
            return None

    def _events_from_payload(self, payload: dict[str, Any], parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        events: list[ScanEvent] = [_make_event(
            event_type="raw_rir_data",
            value=f"Maltiverse record for {parent_event.value}",
            slug=self.slug,
            parent_event=parent_event,
            ctx=ctx,
            risk_score=0,
            confidence=75,
            tags=["maltiverse", "raw"],
            raw_payload={"payload": payload, "spiderfoot_parity": True},
        )]

        if parent_event.event_type in {"ip", "affiliate_ipaddr"}:
            reported_ip = str(payload.get("ip_addr", "") or "").strip()
            if reported_ip and reported_ip != parent_event.value:
                return events
            blacklist = payload.get("blacklist") or []
            if not isinstance(blacklist, list):
                blacklist = []
            age_limit_days = _module_int(ctx, self.slug, _cti_slug(self.slug), "age_limit_days", 30)
            descriptions: list[str] = []
            for blacklisted_record in blacklist:
                if not isinstance(blacklisted_record, dict):
                    continue
                last_seen = str(blacklisted_record.get("last_seen", "") or "").strip()
                if not last_seen:
                    continue
                try:
                    last_seen_date = datetime.strptime(last_seen, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                except Exception:
                    continue
                if age_limit_days > 0 and (datetime.now(timezone.utc) - last_seen_date).days > age_limit_days:
                    continue
                description = str(blacklisted_record.get("description", "") or "").strip()
                if description:
                    descriptions.append(description)
            if not descriptions:
                return events
            label = f"Maltiverse [{parent_event.value}]\n" + "\n".join(
                f" - DESCRIPTION : {description}" for description in descriptions
            )
            event_type = "malicious_affiliate_ipaddr" if parent_event.event_type == "affiliate_ipaddr" else "malicious_ip"
            events.append(_make_event(
                event_type=event_type,
                value=label,
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=90,
                confidence=88,
                tags=["maltiverse", "malicious"],
                raw_payload={"payload": payload, "spiderfoot_parity": True},
            ))
            return events

        classification = str(payload.get("classification", "") or "").strip().lower()
        is_ioc = bool(payload.get("is_ioc"))
        blacklist = payload.get("blacklist") or []
        if not isinstance(blacklist, list):
            blacklist = []
        suspicious = classification in {"malicious", "suspicious"} or is_ioc or bool(blacklist)
        if not suspicious:
            return events

        label = _event_value("Maltiverse", parent_event.value, self._endpoint_for_event(parent_event) or "https://maltiverse.com/")
        events.extend(_emit_malicious_and_blacklisted(
            parent_event=parent_event,
            ctx=ctx,
            slug=self.slug,
            value=label if parent_event.event_type != "url" else parent_event.value,
            source_url=self._endpoint_for_event(parent_event) or "https://maltiverse.com/",
            tags=["maltiverse"],
            risk_score=90 if classification == "malicious" else 75,
            confidence=88,
        ))
        return events
