"""Wave 2 no-key OSINT modules for the first-party CTI engine."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from html import unescape
import ipaddress
import json
from pathlib import Path
import re
import socket
import ssl
import subprocess
import urllib.parse
from typing import Any, AsyncIterator

from ..events import ScanEvent
from ..module_base import BaseModule
from ..targets import DOMAIN_RX
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


URL_RX = re.compile(r"https?://[^\s\"'<>]+", re.I)
EMAIL_TEXT_RX = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
ONION_RX = re.compile(r"([a-z2-7]{16,56}\.onion)", re.I)
MARKUP_RX = re.compile(r"</?mark>", re.I)
TXT_VALUE_RX = re.compile(r'"([^"]+)"')
SPF_INCLUDE_RX = re.compile(r"include:([A-Z0-9._-]+\.[A-Z]{2,})", re.I)

REPO_ROOT = Path(__file__).resolve().parents[3]
SPIDERFOOT_SUBDOMAINS = REPO_ROOT / "spiderfoot-master" / "spiderfoot" / "dicts" / "subdomains.txt"
SPIDERFOOT_SUBDOMAINS_TOP = REPO_ROOT / "spiderfoot-master" / "spiderfoot" / "dicts" / "subdomains-10000.txt"


GENERIC_EMAIL_USERS = {
    "abuse", "admin", "billing", "compliance", "devnull", "dns", "ftp",
    "hostmaster", "inoc", "ispfeedback", "ispsupport", "list-request", "list",
    "maildaemon", "marketing", "noc", "no-reply", "noreply", "null", "peering",
    "peering-notify", "peering-request", "phish", "phishing", "postmaster",
    "privacy", "registrar", "registry", "root", "routing-registry", "rr",
    "sales", "security", "spam", "support", "sysadmin",
    "undisclosed-recipients", "unsubscribe", "usenet", "uucp", "webmaster", "www",
}


def _fetch_json(url: str, timeout: int, ctx, slug: str) -> Any | None:
    content = _fetch_text(url, timeout, ctx, slug, accept="application/json, text/plain, */*")
    if content is None:
        return None
    try:
        return json.loads(content)
    except json.JSONDecodeError as exc:
        ctx.warning(f"{slug} returned invalid JSON: {exc}", slug)
        return None


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


def _matches_target_or_parent(candidate: str, root: str) -> bool:
    candidate = _normalize_host(candidate)
    root = _normalize_host(root)
    if not candidate or not root:
        return False
    if candidate == root:
        return True
    return candidate.endswith("." + root) or root.endswith("." + candidate)


def _matches_exact_target(candidate: str, root: str) -> bool:
    return _normalize_host(candidate) == _normalize_host(root)


def _strip_markup(value: str) -> str:
    return unescape(MARKUP_RX.sub("", str(value or "")).strip())


def _extract_urls(value: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for match in URL_RX.findall(_strip_markup(value)):
        candidate = match.rstrip(").,;]}>")
        if candidate and candidate not in seen:
            seen.add(candidate)
            found.append(candidate)
    return found


def _extract_emails(value: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for match in EMAIL_TEXT_RX.findall(_strip_markup(value)):
        candidate = match.strip().lower()
        if candidate and candidate not in seen:
            seen.add(candidate)
            found.append(candidate)
    return found


def _looks_like_domain(value: str) -> bool:
    candidate = _normalize_host(value)
    if not candidate or _valid_ip(candidate):
        return False
    return bool(DOMAIN_RX.match(candidate))


def _name_to_string(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    if not isinstance(value, (list, tuple)):
        return ""
    parts: list[str] = []
    for group in value:
        if not isinstance(group, (list, tuple)):
            continue
        for item in group:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                key = str(item[0] or "").strip()
                val = str(item[1] or "").strip()
                if key and val:
                    parts.append(f"{key}={val}")
    return ", ".join(parts)


def _parse_not_after(value: str) -> datetime | None:
    candidate = str(value or "").strip()
    if not candidate:
        return None
    try:
        parsed = datetime.strptime(candidate, "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc)


def _certificate_hosts(cert: dict[str, Any]) -> list[str]:
    hosts: list[str] = []
    for san_type, san_value in cert.get("subjectAltName") or []:
        if str(san_type).lower() == "dns":
            host = _normalize_host(str(san_value or ""))
            if host and host not in hosts:
                hosts.append(host)

    subject = cert.get("subject") or ()
    for group in subject:
        if not isinstance(group, (list, tuple)):
            continue
        for item in group:
            if not isinstance(item, (list, tuple)) or len(item) != 2:
                continue
            key = str(item[0] or "").strip().lower()
            if key != "commonname":
                continue
            host = _normalize_host(str(item[1] or ""))
            if host and host not in hosts:
                hosts.append(host)
    return hosts


def _host_matches_certificate(host: str, cert_hosts: list[str]) -> bool:
    target = _normalize_host(host)
    if not target:
        return False
    target_suffix = ".".join(target.split(".")[1:]) if "." in target else ""
    for candidate in cert_hosts:
        name = _normalize_host(candidate)
        if not name:
            continue
        if name == target:
            return True
        if name == target_suffix:
            return True
        if name.startswith("*.") and target_suffix and name[2:] == target_suffix:
            return True
    return False


def _public_repo_value(repo: str, url: str) -> str:
    if url:
        return f"{repo}\n<SFURL>{url}</SFURL>"
    return repo


def _base_domain(value: str) -> str:
    host = _normalize_host(value)
    parts = [part for part in host.split(".") if part]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def _dns_lookup(host: str) -> bool:
    try:
        return bool(socket.getaddrinfo(host, None))
    except OSError:
        return False


def _resolve_hosts(hosts: list[str], max_workers: int) -> dict[str, bool]:
    if not hosts:
        return {}
    results: dict[str, bool] = {}
    workers = max(1, min(max_workers, len(hosts)))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {executor.submit(_dns_lookup, host): host for host in hosts}
        for future in as_completed(future_map):
            host = future_map[future]
            try:
                results[host] = bool(future.result())
            except Exception:
                results[host] = False
    return results


def _has_dns_wildcard(domain: str) -> bool:
    probe = f"cti-wildcard-check-{abs(hash(domain)) % 1_000_000}.{domain}"
    return _dns_lookup(probe)


def _load_subdomain_words(*, include_common: bool, include_top: bool) -> list[str]:
    words: list[str] = []
    for path in (
        SPIDERFOOT_SUBDOMAINS if include_common else None,
        SPIDERFOOT_SUBDOMAINS_TOP if include_top else None,
    ):
        if path is None or not path.exists():
            continue
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            candidate = line.strip().lower()
            if candidate and candidate not in words:
                words.append(candidate)
    if words:
        return words
    if not include_common and not include_top:
        return []
    return [
        "www", "mail", "ftp", "api", "dev", "staging", "admin", "blog", "shop",
        "cdn", "vpn", "remote", "mx", "ns1", "ns2",
    ]


def _nslookup(domain: str, record_type: str, timeout: int) -> str:
    try:
        proc = subprocess.run(
            ["nslookup", f"-type={record_type}", domain],
            capture_output=True,
            text=True,
            timeout=max(2, timeout),
            check=False,
        )
    except Exception:
        return ""
    return proc.stdout or ""


def _parse_nslookup_output(record_type: str, content: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    if not content:
        return rows
    raw = str(content)
    if record_type == "CNAME":
        matches = re.findall(r"canonical name\s*=\s*([^\s]+)", raw, re.I)
        for match in matches:
            rows.append({"type": "CNAME", "value": match.rstrip(".").lower(), "raw": f"CNAME {match.rstrip('.')}"})
    elif record_type == "MX":
        matches = re.findall(r"mail exchanger\s*=\s*(?:\d+\s+)?([^\s]+)", raw, re.I)
        for match in matches:
            rows.append({"type": "MX", "value": match.rstrip(".").lower(), "raw": f"MX {match.rstrip('.')}"})
    elif record_type == "NS":
        matches = re.findall(r"nameserver\s*=\s*([^\s]+)", raw, re.I)
        for match in matches:
            rows.append({"type": "NS", "value": match.rstrip(".").lower(), "raw": f"NS {match.rstrip('.')}"})
    elif record_type == "TXT":
        seen: set[str] = set()
        for match in TXT_VALUE_RX.findall(raw):
            value = match.strip()
            if not value or value in seen:
                continue
            seen.add(value)
            rows.append({"type": "TXT", "value": value, "raw": f'TXT "{value}"'})
    return rows


def _spf_include_domains(value: str) -> list[str]:
    domains: list[str] = []
    seen: set[str] = set()
    for match in SPF_INCLUDE_RX.findall(str(value or "")):
        candidate = match.strip().lower()
        if "_" in candidate or candidate in seen:
            continue
        seen.add(candidate)
        domains.append(candidate)
    return domains


def _is_generic_email(value: str) -> bool:
    local_part = str(value or "").split("@", 1)[0].strip().lower()
    return local_part in GENERIC_EMAIL_USERS


class AhmiaModule(BaseModule):
    slug = "ahmia"
    name = "Ahmia"
    watched_types = {"domain", "email", "human_name"}
    produced_types = {"darknet_mention_url", "darknet_mention_content"}
    requires_key = False

    SEARCH_URL = "https://ahmia.fi/search/?q={query}"
    RESULT_LINK_RX = re.compile(r'redirect_url=(.[^"]+)"', re.I | re.S)

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        if event.event_type == "human_name" and not _module_bool(
            ctx,
            self.slug,
            _cti_slug(self.slug),
            ("search_human_names", "fullnames"),
            True,
        ):
            return
        timeout = _http_timeout(ctx)
        endpoint = self.SEARCH_URL.format(
            query=urllib.parse.quote(event.value, safe=""),
        )
        content = _fetch_text(endpoint, timeout, ctx, self.slug, accept="text/html, */*")
        if not content:
            return
        fetch_darknet_pages = _module_bool(
            ctx,
            self.slug,
            _cti_slug(self.slug),
            ("fetch_darknet_pages", "fetchlinks"),
            True,
        )
        for child in self._events_from_search_page(
            content,
            event,
            ctx,
            timeout=timeout,
            fetch_darknet_pages=fetch_darknet_pages,
        ):
            yield child

    def _events_from_search_page(
        self,
        content: str,
        parent_event: ScanEvent,
        ctx,
        *,
        timeout: int,
        fetch_darknet_pages: bool = True,
    ) -> list[ScanEvent]:
        events: list[ScanEvent] = []
        target = str(parent_event.value or "")
        seen_urls: set[str] = set()

        for match in self.RESULT_LINK_RX.findall(str(content or "")):
            link = urllib.parse.unquote(str(match or "").strip())
            if not link or link in seen_urls:
                continue
            seen_urls.add(link)

            host = _normalize_host(link)
            if not ONION_RX.search(host):
                continue

            if not fetch_darknet_pages:
                events.append(self._darknet_url_event(link, parent_event, ctx))
                continue

            page = _fetch_text(link, timeout, ctx, self.slug, accept="text/html, */*")
            if not page or target not in page:
                continue

            url_event = self._darknet_url_event(link, parent_event, ctx)
            events.append(url_event)

            try:
                start_index = max(0, page.index(target) - 120)
            except ValueError:
                continue
            end_index = min(len(page), start_index + len(target) + 240)
            snippet = page[start_index:end_index]
            events.append(_make_event(
                event_type="darknet_mention_content",
                value=f"...{snippet}...",
                slug=self.slug,
                parent_event=url_event,
                ctx=ctx,
                risk_score=25,
                confidence=70,
                tags=["ahmia", "darknet", "mention", "content"],
                raw_payload={"url": link, "spiderfoot_parity": True},
            ))
        return events

    def _darknet_url_event(self, url: str, parent_event: ScanEvent, ctx) -> ScanEvent:
        return _make_event(
            event_type="darknet_mention_url",
            value=url,
            slug=self.slug,
            parent_event=parent_event,
            ctx=ctx,
            risk_score=30,
            confidence=75,
            tags=["ahmia", "darknet", "mention", "url"],
            raw_payload={"url": url, "spiderfoot_parity": True},
        )

    def _events_from_payload(self, payload: dict[str, Any], parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        events: list[ScanEvent] = []
        seen_urls: set[str] = set()
        rows = payload.get("results") or []
        if not isinstance(rows, list):
            return events

        for row in rows:
            if not isinstance(row, dict):
                continue
            url = str(row.get("url", "") or "").strip()
            host = _normalize_host(url)
            onion_match = ONION_RX.search(host)
            if not url or not onion_match or url in seen_urls:
                continue
            seen_urls.add(url)
            url_event = _make_event(
                event_type="darknet_mention_url",
                value=url,
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=30,
                confidence=75,
                tags=["ahmia", "darknet", "mention", "url"],
                raw_payload={"row": row, "spiderfoot_parity": True},
            )
            events.append(url_event)

            snippet_parts = [
                str(row.get("title", "") or "").strip(),
                str(row.get("description", "") or "").strip(),
            ]
            snippet = " ".join(part for part in snippet_parts if part).strip()
            if snippet:
                events.append(_make_event(
                    event_type="darknet_mention_content",
                    value=f"...{snippet[:320]}...",
                    slug=self.slug,
                    parent_event=url_event,
                    ctx=ctx,
                    risk_score=25,
                    confidence=70,
                    tags=["ahmia", "darknet", "mention", "content"],
                    raw_payload={"row": row, "spiderfoot_parity": True},
                ))
        return events


class DnsBruteforceModule(BaseModule):
    slug = "dns-bruteforce"
    name = "DNS Brute-forcer"
    watched_types = {"domain", "internet_name"}
    produced_types = {"internet_name"}
    requires_key = False

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        root = _root_host(ctx, event)
        commons = _module_bool(ctx, self.slug, _cti_slug(self.slug), "commons", True)
        top10000 = _module_bool(ctx, self.slug, _cti_slug(self.slug), "top10000", False)
        numbersuffix = _module_bool(ctx, self.slug, _cti_slug(self.slug), "numbersuffix", True)
        numbersuffixlimit = _module_bool(ctx, self.slug, _cti_slug(self.slug), "numbersuffixlimit", True)
        skip_wildcard = _module_bool(ctx, self.slug, _cti_slug(self.slug), "skipcommonwildcard", True)
        domainonly = _module_bool(ctx, self.slug, _cti_slug(self.slug), "domainonly", True)
        max_workers = max(1, min(100, _module_int(ctx, self.slug, _cti_slug(self.slug), "_maxthreads", 100)))

        candidates: list[str] = []
        if event.event_type == "internet_name" and not _matches_exact_target(event.value, root):
            if not numbersuffix:
                return
            parts = _normalize_host(event.value).split(".", 1)
            if len(parts) != 2:
                return
            host, domain = parts
            if skip_wildcard and _has_dns_wildcard(domain):
                ctx.debug(f"Wildcard DNS detected on {domain}; skipping host iteration.", self.slug)
                return
            candidates = self._number_suffix_hosts(host, domain)
        else:
            domain = _normalize_host(event.value)
            if event.event_type == "internet_name" and domainonly and not _matches_exact_target(domain, root):
                return
            if skip_wildcard and _has_dns_wildcard(domain):
                ctx.debug(f"Wildcard DNS detected on {domain}; skipping brute-force.", self.slug)
                return
            words = _load_subdomain_words(include_common=commons, include_top=top10000)
            candidates = [f"{word}.{domain}" for word in words]
            if numbersuffix and not numbersuffixlimit:
                extra: list[str] = []
                for word in words:
                    extra.extend(self._number_suffix_hosts(word, domain))
                candidates.extend(extra)

        unique_candidates = sorted({candidate for candidate in candidates if candidate})
        if not unique_candidates:
            return
        results = _resolve_hosts(unique_candidates, max_workers)
        for child in self._events_from_resolutions(results, event, ctx):
            yield child

    def _number_suffix_hosts(self, host: str, domain: str) -> list[str]:
        rows: list[str] = []
        for index in range(10):
            rows.extend([
                f"{host}{index}.{domain}",
                f"{host}0{index}.{domain}",
                f"{host}00{index}.{domain}",
                f"{host}-{index}.{domain}",
                f"{host}-0{index}.{domain}",
                f"{host}-00{index}.{domain}",
            ])
        return rows

    def _events_from_resolutions(self, resolutions: dict[str, bool], parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        events: list[ScanEvent] = []
        for host in sorted(resolutions):
            if not resolutions[host]:
                continue
            events.append(_make_event(
                event_type="internet_name",
                value=host,
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=5,
                confidence=80,
                tags=["dns", "bruteforce", "hostname"],
                raw_payload={"resolved": True, "spiderfoot_parity": True},
            ))
        return events


class DnsRawModule(BaseModule):
    slug = "dns-raw"
    name = "DNS Raw Records"
    watched_types = {"domain", "domain_name_parent", "internet_name"}
    produced_types = {
        "provider_mail",
        "provider_dns",
        "raw_dns_records",
        "dns_text",
        "dns_spf",
        "internet_name",
        "internet_name_unresolved",
        "affiliate_internet_name",
        "affiliate_internet_name_unresolved",
    }
    requires_key = False

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        timeout = _http_timeout(ctx)
        records: list[dict[str, str]] = []
        for record_type in ("CNAME", "MX", "NS", "TXT"):
            output = _nslookup(event.value, record_type, timeout)
            records.extend(_parse_nslookup_output(record_type, output))
        if not records:
            return
        for child in self._events_from_records(records, event, ctx):
            yield child

    def _events_from_records(self, records: list[dict[str, str]], parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        events: list[ScanEvent] = []
        related_hosts: list[str] = []
        seen_related: set[str] = set()
        seen_raw: set[str] = set()
        seen_mail: set[str] = set()
        seen_dns: set[str] = set()
        seen_text: set[str] = set()
        seen_spf: set[str] = set()
        root = _root_host(ctx, parent_event)
        verify = _module_bool(ctx, self.slug, _cti_slug(self.slug), "verify", True)

        for record in records:
            raw_value = str(record.get("raw", "") or "").strip()
            if raw_value and raw_value not in seen_raw:
                seen_raw.add(raw_value)
                events.append(_make_event(
                    event_type="raw_dns_records",
                    value=raw_value,
                    slug=self.slug,
                    parent_event=parent_event,
                    ctx=ctx,
                    risk_score=0,
                    confidence=85,
                    tags=["dns", "raw", "record"],
                    raw_payload={"record": record, "spiderfoot_parity": True},
                ))

            record_type = str(record.get("type", "") or "").upper()
            value = str(record.get("value", "") or "").strip()
            if not value:
                continue

            if record_type == "MX":
                provider = value.lower().rstrip(".")
                if provider not in seen_mail:
                    seen_mail.add(provider)
                    events.append(_make_event(
                        event_type="provider_mail",
                        value=provider,
                        slug=self.slug,
                        parent_event=parent_event,
                        ctx=ctx,
                        risk_score=0,
                        confidence=82,
                        tags=["dns", "mx", "provider"],
                        raw_payload={"record": record, "spiderfoot_parity": True},
                    ))
                if provider not in seen_related:
                    seen_related.add(provider)
                    related_hosts.append(provider)
            elif record_type == "NS":
                provider = value.lower().rstrip(".")
                if provider not in seen_dns:
                    seen_dns.add(provider)
                    events.append(_make_event(
                        event_type="provider_dns",
                        value=provider,
                        slug=self.slug,
                        parent_event=parent_event,
                        ctx=ctx,
                        risk_score=0,
                        confidence=82,
                        tags=["dns", "ns", "provider"],
                        raw_payload={"record": record, "spiderfoot_parity": True},
                    ))
                if provider not in seen_related:
                    seen_related.add(provider)
                    related_hosts.append(provider)
            elif record_type == "TXT":
                if value not in seen_text:
                    seen_text.add(value)
                    events.append(_make_event(
                        event_type="dns_text",
                        value=value,
                        slug=self.slug,
                        parent_event=parent_event,
                        ctx=ctx,
                        risk_score=0,
                        confidence=80,
                        tags=["dns", "txt"],
                        raw_payload={"record": record, "spiderfoot_parity": True},
                    ))
                if "v=spf" in value.lower() or "spf2.0/" in value.lower():
                    if value not in seen_spf:
                        seen_spf.add(value)
                        events.append(_make_event(
                            event_type="dns_spf",
                            value=value,
                            slug=self.slug,
                            parent_event=parent_event,
                            ctx=ctx,
                            risk_score=0,
                            confidence=80,
                            tags=["dns", "spf"],
                            raw_payload={"record": record, "spiderfoot_parity": True},
                        ))
                    for domain in _spf_include_domains(value):
                        if domain not in seen_related:
                            seen_related.add(domain)
                            related_hosts.append(domain)
            elif record_type == "CNAME":
                host = value.lower().rstrip(".")
                if host not in seen_related:
                    seen_related.add(host)
                    related_hosts.append(host)

        for host in related_hosts:
            if _matches_target_or_parent(host, root):
                event_type = "internet_name"
            else:
                event_type = "affiliate_internet_name"
            if verify and not _host_resolves(host):
                event_type += "_unresolved"
            events.append(_make_event(
                event_type=event_type,
                value=host,
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=5 if event_type.startswith("affiliate_") else 3,
                confidence=76,
                tags=["dns", "related_host"],
                raw_payload={"related_host": host, "spiderfoot_parity": True},
            ))
        return events


class DnsGrepModule(BaseModule):
    slug = "dnsgrep"
    name = "DNSGrep"
    watched_types = {"domain"}
    produced_types = {"internet_name", "internet_name_unresolved", "raw_rir_data"}
    requires_key = False

    LOOKUP_URL = "https://dns.bufferover.run/dns?q=.{domain}"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        timeout = _module_int(ctx, self.slug, _cti_slug(self.slug), "timeout", 30)
        endpoint = self.LOOKUP_URL.format(domain=urllib.parse.quote(event.value, safe=""))
        payload = _fetch_json(endpoint, timeout, ctx, self.slug)
        if not isinstance(payload, dict):
            return
        for child in self._events_from_payload(payload, event, ctx):
            yield child

    def _events_from_payload(self, payload: dict[str, Any], parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        events: list[ScanEvent] = [
            _make_event(
                event_type="raw_rir_data",
                value=str(payload),
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=0,
                confidence=84,
                tags=["dnsgrep", "raw", "pdns"],
                raw_payload={"spiderfoot_parity": True},
            )
        ]
        root = _root_host(ctx, parent_event)
        verify = _module_bool(ctx, self.slug, _cti_slug(self.slug), "dns_resolve", True)
        seen: set[str] = set()
        for key in ("FDNS_A", "RDNS"):
            values = payload.get(key) or []
            if not isinstance(values, list):
                continue
            for row in values:
                candidate = str(row or "").strip()
                if "," not in candidate:
                    continue
                _, host = candidate.split(",", 1)
                hostname = _normalize_host(host)
                if not hostname or hostname in seen or not _matches_target_or_parent(hostname, root):
                    continue
                seen.add(hostname)
                event_type = "internet_name"
                if verify and not _host_resolves(hostname):
                    event_type = "internet_name_unresolved"
                events.append(_make_event(
                    event_type=event_type,
                    value=hostname,
                    slug=self.slug,
                    parent_event=parent_event,
                    ctx=ctx,
                    risk_score=5,
                    confidence=78,
                    tags=["dnsgrep", "pdns", "hostname"],
                    raw_payload={"source_key": key, "row": candidate, "spiderfoot_parity": True},
                ))
        return events


class DuckDuckGoModule(BaseModule):
    slug = "duckduckgo"
    name = "DuckDuckGo"
    watched_types = {"domain", "domain_name_parent", "internet_name", "affiliate_internet_name"}
    produced_types = {
        "description_category",
        "description_abstract",
        "affiliate_description_category",
        "affiliate_description_abstract",
    }
    requires_key = False

    LOOKUP_URL = "https://api.duckduckgo.com/?q={query}&format=json&pretty=1"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        query_value = event.value
        if event.event_type.startswith("affiliate_") and _module_bool(
            ctx, self.slug, _cti_slug(self.slug), "affiliatedomains", True
        ):
            query_value = _base_domain(event.value)
        endpoint = self.LOOKUP_URL.format(query=urllib.parse.quote(query_value, safe=""))
        payload = _fetch_json(endpoint, _http_timeout(ctx), ctx, self.slug)
        if not isinstance(payload, dict):
            return
        for child in self._events_from_payload(payload, event, ctx):
            yield child

    def _events_from_payload(self, payload: dict[str, Any], parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        heading = str(payload.get("Heading", "") or "").strip()
        if not heading:
            return []

        events: list[ScanEvent] = []
        prefix = "affiliate_" if parent_event.event_type.startswith("affiliate_") else ""

        abstract = str(payload.get("AbstractText", "") or "").strip()
        if abstract:
            events.append(_make_event(
                event_type=f"{prefix}description_abstract",
                value=abstract,
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=0,
                confidence=70,
                tags=["duckduckgo", "description", "abstract"],
                raw_payload={"spiderfoot_parity": True},
            ))

        seen_categories: set[str] = set()
        for category in self._related_topics(payload.get("RelatedTopics")):
            if category in seen_categories:
                continue
            seen_categories.add(category)
            events.append(_make_event(
                event_type=f"{prefix}description_category",
                value=category,
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=0,
                confidence=66,
                tags=["duckduckgo", "description", "category"],
                raw_payload={"spiderfoot_parity": True},
            ))
        return events

    def _related_topics(self, value: Any) -> list[str]:
        rows: list[str] = []
        if not isinstance(value, list):
            return rows
        for item in value:
            if not isinstance(item, dict):
                continue
            text = str(item.get("Text", "") or "").strip()
            if text:
                rows.append(text)
        return rows


class GrepAppModule(BaseModule):
    slug = "grep-app"
    name = "grep.app"
    watched_types = {"domain"}
    produced_types = {
        "email",
        "email_generic",
        "domain_name",
        "internet_name",
        "internet_name_unresolved",
        "linked_url_internal",
        "raw_rir_data",
    }
    requires_key = False

    SEARCH_URL = "https://grep.app/api/search?q={query}&page={page}"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        max_pages = max(1, min(20, _module_int(ctx, self.slug, _cti_slug(self.slug), "max_pages", 20)))
        timeout = _http_timeout(ctx)
        for page in range(1, max_pages + 1):
            endpoint = self.SEARCH_URL.format(
                query=urllib.parse.quote(event.value, safe=""),
                page=page,
            )
            payload = _fetch_json(endpoint, timeout, ctx, self.slug)
            if not isinstance(payload, dict):
                return
            page_events = self._events_from_payload(payload, event, ctx)
            if not page_events:
                return
            for child in page_events:
                yield child
            if not self._has_more_pages(payload, page):
                break

    def _has_more_pages(self, payload: dict[str, Any], page: int) -> bool:
        facets = payload.get("facets") or {}
        hits = payload.get("hits") or {}
        total = 0
        if isinstance(facets, dict):
            total = int(facets.get("count", 0) or 0)
        if not total and isinstance(hits, dict):
            raw_total = hits.get("total", 0)
            if isinstance(raw_total, dict):
                total = int(raw_total.get("value", 0) or 0)
            else:
                total = int(raw_total or 0)
        return total > page * 10

    def _events_from_payload(self, payload: dict[str, Any], parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        hits = payload.get("hits") or {}
        rows = hits.get("hits") if isinstance(hits, dict) else None
        if not isinstance(rows, list) or not rows:
            return []

        events: list[ScanEvent] = []
        hosts: list[str] = []
        seen_hosts: set[str] = set()
        seen_links: set[str] = set()
        seen_emails: set[str] = set()
        root = _root_host(ctx, parent_event)
        verify = _module_bool(ctx, self.slug, _cti_slug(self.slug), "dns_resolve", True)

        for row in rows:
            if not isinstance(row, dict):
                continue
            events.append(_make_event(
                event_type="raw_rir_data",
                value=json.dumps(row, ensure_ascii=False),
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=0,
                confidence=80,
                tags=["grepapp", "raw", "code"],
                raw_payload={"spiderfoot_parity": True},
            ))
            source = row.get("_source") or {}
            if not isinstance(source, dict):
                continue
            content = source.get("content") or {}
            snippet = ""
            if isinstance(content, dict):
                snippet = str(content.get("snippet", "") or "")
            cleaned = _strip_markup(snippet)
            for link in _extract_urls(cleaned):
                if link in seen_links:
                    continue
                host = _normalize_host(link)
                if not _matches_target_or_parent(host, root):
                    continue
                seen_links.add(link)
                events.append(_make_event(
                    event_type="linked_url_internal",
                    value=link,
                    slug=self.slug,
                    parent_event=parent_event,
                    ctx=ctx,
                    risk_score=5,
                    confidence=75,
                    tags=["grepapp", "code", "url"],
                    raw_payload={"row": row, "spiderfoot_parity": True},
                ))
                if host and host not in seen_hosts:
                    seen_hosts.add(host)
                    hosts.append(host)

            for email in _extract_emails(cleaned):
                if email in seen_emails:
                    continue
                mail_domain = email.split("@", 1)[1]
                if not _matches_target_or_parent(mail_domain, root):
                    continue
                seen_emails.add(email)
                events.append(_make_event(
                    event_type="email_generic" if _is_generic_email(email) else "email",
                    value=email,
                    slug=self.slug,
                    parent_event=parent_event,
                    ctx=ctx,
                    risk_score=8,
                    confidence=80,
                    tags=["grepapp", "code", "email"],
                    raw_payload={"row": row, "spiderfoot_parity": True},
                ))

        for host in hosts:
            event_type = "internet_name"
            if verify and not _host_resolves(host):
                event_type = "internet_name_unresolved"
            events.append(_make_event(
                event_type=event_type,
                value=host,
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=5,
                confidence=74,
                tags=["grepapp", "code", "hostname"],
                raw_payload={"spiderfoot_parity": True},
            ))
            if _looks_like_domain(host):
                events.append(_make_event(
                    event_type="domain_name",
                    value=host,
                    slug=self.slug,
                    parent_event=parent_event,
                    ctx=ctx,
                    risk_score=3,
                    confidence=72,
                    tags=["grepapp", "code", "domain"],
                    raw_payload={"spiderfoot_parity": True},
                ))
        return events


class SearchcodeModule(BaseModule):
    slug = "searchcode"
    name = "searchcode"
    watched_types = {"domain"}
    produced_types = {
        "email",
        "email_generic",
        "linked_url_internal",
        "public_code_repo",
        "raw_rir_data",
        "internet_name",
        "internet_name_unresolved",
    }
    requires_key = False

    SEARCH_URL = "https://searchcode.com/api/codesearch_I/?q={query}&p={page}&per_page=100"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        max_pages = max(1, min(10, _module_int(ctx, self.slug, _cti_slug(self.slug), "max_pages", 10)))
        timeout = _http_timeout(ctx)
        for page in range(max_pages):
            endpoint = self.SEARCH_URL.format(
                query=urllib.parse.quote(event.value, safe=""),
                page=page,
            )
            payload = _fetch_json(endpoint, timeout, ctx, self.slug)
            if not isinstance(payload, dict):
                return
            page_events = self._events_from_payload(payload, event, ctx)
            if not page_events:
                return
            for child in page_events:
                yield child
            if not payload.get("nextpage"):
                break

    def _events_from_payload(self, payload: dict[str, Any], parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        rows = payload.get("results") or []
        if not isinstance(rows, list) or not rows:
            return []

        events: list[ScanEvent] = []
        root = _root_host(ctx, parent_event)
        verify = _module_bool(ctx, self.slug, _cti_slug(self.slug), "dns_resolve", True)
        seen_repo: set[str] = set()
        seen_links: set[str] = set()
        seen_hosts: set[str] = set()
        seen_emails: set[str] = set()

        for row in rows:
            if not isinstance(row, dict):
                continue

            if parent_event.value in json.dumps(row, ensure_ascii=False):
                repo = str(row.get("repo", "") or "").strip()
                url = str(row.get("url", "") or "").strip()
                if repo and repo not in seen_repo:
                    seen_repo.add(repo)
                    events.append(_make_event(
                        event_type="public_code_repo",
                        value=_public_repo_value(repo, url),
                        slug=self.slug,
                        parent_event=parent_event,
                        ctx=ctx,
                        risk_score=10,
                        confidence=78,
                        tags=["searchcode", "code", "repository"],
                        raw_payload={"row": row, "spiderfoot_parity": True},
                    ))
                    events.append(_make_event(
                        event_type="raw_rir_data",
                        value=json.dumps(row, ensure_ascii=False),
                        slug=self.slug,
                        parent_event=parent_event,
                        ctx=ctx,
                        risk_score=0,
                        confidence=80,
                        tags=["searchcode", "raw", "code"],
                        raw_payload={"spiderfoot_parity": True},
                    ))

            lines = row.get("lines") or {}
            if not isinstance(lines, dict):
                continue
            for line in lines.values():
                cleaned = _strip_markup(str(line or ""))
                for email in _extract_emails(cleaned):
                    if email in seen_emails:
                        continue
                    mail_domain = email.split("@", 1)[1]
                    if not _matches_target_or_parent(mail_domain, root):
                        continue
                    seen_emails.add(email)
                    events.append(_make_event(
                        event_type="email_generic" if _is_generic_email(email) else "email",
                        value=email,
                        slug=self.slug,
                        parent_event=parent_event,
                        ctx=ctx,
                        risk_score=8,
                        confidence=80,
                        tags=["searchcode", "code", "email"],
                        raw_payload={"row": row, "spiderfoot_parity": True},
                    ))

                for link in _extract_urls(cleaned):
                    if link in seen_links:
                        continue
                    host = _normalize_host(link)
                    if not _matches_target_or_parent(host, root):
                        continue
                    seen_links.add(link)
                    events.append(_make_event(
                        event_type="linked_url_internal",
                        value=link,
                        slug=self.slug,
                        parent_event=parent_event,
                        ctx=ctx,
                        risk_score=5,
                        confidence=76,
                        tags=["searchcode", "code", "url"],
                        raw_payload={"row": row, "spiderfoot_parity": True},
                    ))
                    if host and host not in seen_hosts:
                        seen_hosts.add(host)
                        event_type = "internet_name"
                        if verify and not _host_resolves(host):
                            event_type = "internet_name_unresolved"
                        events.append(_make_event(
                            event_type=event_type,
                            value=host,
                            slug=self.slug,
                            parent_event=parent_event,
                            ctx=ctx,
                            risk_score=5,
                            confidence=72,
                            tags=["searchcode", "code", "hostname"],
                            raw_payload={"row": row, "spiderfoot_parity": True},
                        ))
        return events


class SslAnalyzerModule(BaseModule):
    slug = "ssl-analyzer"
    name = "SSL Certificate Analyzer"
    watched_types = {"domain", "internet_name", "linked_url_internal", "ip"}
    produced_types = {
        "tcp_port_open",
        "internet_name",
        "internet_name_unresolved",
        "co_hosted_site",
        "co_hosted_site_domain",
        "ssl_certificate_issued",
        "ssl_certificate_issuer",
        "ssl_certificate_mismatch",
        "ssl_certificate_expired",
        "ssl_certificate_expiring",
        "ssl_certificate_raw",
        "domain_name",
    }
    requires_key = False

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        try_http = _module_bool(ctx, self.slug, _cti_slug(self.slug), "tryhttp", True)
        verify_hosts = _module_bool(ctx, self.slug, _cti_slug(self.slug), "verify", True)
        timeout = _module_int(ctx, self.slug, _cti_slug(self.slug), "ssltimeout", 10)
        expiring_days = _module_int(ctx, self.slug, _cti_slug(self.slug), "certexpiringdays", 30)

        host = event.value
        port = 443
        if event.event_type == "linked_url_internal":
            if not event.value.lower().startswith("https://") and not try_http:
                return
            parsed = urllib.parse.urlparse(event.value)
            if not parsed.hostname:
                return
            host = parsed.hostname
            if parsed.port:
                port = parsed.port

        try:
            cert, pem = self._connect_certificate(host, port, timeout)
        except Exception as exc:
            ctx.info(f"Unable to SSL-connect to {host} ({exc})", self.slug)
            return

        for child in self._events_from_certificate(cert, pem, host, port, parent_event=event, ctx=ctx, verify_hosts=verify_hosts, expiring_days=expiring_days):
            yield child

    def _connect_certificate(self, host: str, port: int, timeout: int) -> tuple[dict[str, Any], str]:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            server_hostname = None if _valid_ip(host) else host
            with context.wrap_socket(sock, server_hostname=server_hostname) as ssock:
                cert = ssock.getpeercert()
                der = ssock.getpeercert(binary_form=True)
        pem = ssl.DER_cert_to_PEM_cert(der)
        return cert, pem

    def _events_from_certificate(
        self,
        cert: dict[str, Any],
        pem: str,
        host: str,
        port: int,
        *,
        parent_event: ScanEvent,
        ctx,
        verify_hosts: bool = True,
        expiring_days: int = 30,
    ) -> list[ScanEvent]:
        events: list[ScanEvent] = []
        if parent_event.event_type in {"internet_name", "ip"}:
            events.append(_make_event(
                event_type="tcp_port_open",
                value=f"{host}:{port}",
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=0,
                confidence=90,
                tags=["ssl", "tcp", "open"],
                raw_payload={"spiderfoot_parity": True},
            ))

        subject_text = _name_to_string(cert.get("subject"))
        issuer_text = _name_to_string(cert.get("issuer"))
        cert_hosts = _certificate_hosts(cert)
        expiry = _parse_not_after(str(cert.get("notAfter", "") or ""))

        raw_text = str(cert.get("text") or pem or "").strip()
        if raw_text:
            events.append(_make_event(
                event_type="ssl_certificate_raw",
                value=raw_text,
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=0,
                confidence=88,
                tags=["ssl", "certificate", "raw"],
                raw_payload={"spiderfoot_parity": True},
            ))
        if subject_text:
            events.append(_make_event(
                event_type="ssl_certificate_issued",
                value=subject_text,
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=0,
                confidence=84,
                tags=["ssl", "certificate", "issued"],
                raw_payload={"spiderfoot_parity": True},
            ))
        if issuer_text:
            events.append(_make_event(
                event_type="ssl_certificate_issuer",
                value=issuer_text,
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=0,
                confidence=84,
                tags=["ssl", "certificate", "issuer"],
                raw_payload={"spiderfoot_parity": True},
            ))

        if parent_event.event_type != "ip" and cert_hosts and not _host_matches_certificate(host, cert_hosts):
            events.append(_make_event(
                event_type="ssl_certificate_mismatch",
                value=", ".join(cert_hosts),
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=35,
                confidence=82,
                tags=["ssl", "certificate", "mismatch"],
                raw_payload={"spiderfoot_parity": True},
            ))

        root = _root_host(ctx, parent_event)
        seen_domains: set[str] = set()
        for san in cert_hosts:
            domain = san.replace("*.", "")
            if domain in seen_domains:
                continue
            seen_domains.add(domain)
            if _matches_root_target(domain, root):
                event_type = "internet_name"
                if verify_hosts and not _host_resolves(domain):
                    event_type = "internet_name_unresolved"
            else:
                event_type = "co_hosted_site"
            events.append(_make_event(
                event_type=event_type,
                value=domain,
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=5 if event_type == "co_hosted_site" else 0,
                confidence=76,
                tags=["ssl", "certificate", "san"],
                raw_payload={"spiderfoot_parity": True},
            ))
            if _looks_like_domain(domain):
                events.append(_make_event(
                    event_type="co_hosted_site_domain" if event_type == "co_hosted_site" else "domain_name",
                    value=domain,
                    slug=self.slug,
                    parent_event=parent_event,
                    ctx=ctx,
                    risk_score=4 if event_type == "co_hosted_site" else 0,
                    confidence=74,
                    tags=["ssl", "certificate", "domain"],
                    raw_payload={"spiderfoot_parity": True},
                ))

        if expiry is not None:
            expiry_text = expiry.strftime("%Y-%m-%d %H:%M:%S")
            now = datetime.now(timezone.utc)
            if expiry <= now:
                events.append(_make_event(
                    event_type="ssl_certificate_expired",
                    value=expiry_text,
                    slug=self.slug,
                    parent_event=parent_event,
                    ctx=ctx,
                    risk_score=45,
                    confidence=88,
                    tags=["ssl", "certificate", "expired"],
                    raw_payload={"spiderfoot_parity": True},
                ))
            else:
                delta_days = (expiry - now).total_seconds() / 86400
                if delta_days <= max(0, expiring_days):
                    events.append(_make_event(
                        event_type="ssl_certificate_expiring",
                        value=expiry_text,
                        slug=self.slug,
                        parent_event=parent_event,
                        ctx=ctx,
                        risk_score=20,
                        confidence=84,
                        tags=["ssl", "certificate", "expiring"],
                        raw_payload={"spiderfoot_parity": True},
                    ))
        return events


class TldSearcherModule(BaseModule):
    slug = "tld-searcher"
    name = "TLD Searcher"
    watched_types = {"domain", "internet_name"}
    produced_types = {"similardomain"}
    requires_key = False

    TLD_URL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
    _tld_cache: list[str] | None = None
    _wildcard_cache: dict[str, bool] = {}
    PRIORITY_TLDS = ["com", "net", "org", "io", "co", "info", "biz", "app", "dev", "ai", "xyz"]

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        keyword = self._keyword(event.value)
        if not keyword:
            return
        tlds = self._tlds(ctx)
        if not tlds:
            return
        active_only = _module_bool(ctx, self.slug, _cti_slug(self.slug), "activeonly", False)
        skip_wildcards = _module_bool(ctx, self.slug, _cti_slug(self.slug), "skipwildcards", True)
        max_workers = max(1, min(50, _module_int(ctx, self.slug, _cti_slug(self.slug), "_maxthreads", 50)))
        candidates = [f"{keyword}.{tld}" for tld in tlds]
        resolved = _resolve_hosts(candidates, max_workers)
        for child in self._events_from_variants(
            resolved,
            event,
            ctx,
            active_only=active_only,
            skip_wildcards=skip_wildcards,
        ):
            yield child

    def _keyword(self, value: str) -> str:
        host = _normalize_host(value)
        parts = [part for part in host.split(".") if part]
        if len(parts) < 2:
            return ""
        if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in {"ac", "co", "com", "edu", "gov", "net", "org"}:
            return parts[-3]
        return parts[-2]

    def _has_wildcard_tld(self, tld: str) -> bool:
        candidate = str(tld or "").strip().lower().rstrip(".")
        if not candidate:
            return False
        cached = self.__class__._wildcard_cache.get(candidate)
        if cached is not None:
            return cached
        result = _has_dns_wildcard(candidate)
        self.__class__._wildcard_cache[candidate] = result
        return result

    def _tlds(self, ctx) -> list[str]:
        if self.__class__._tld_cache is None:
            payload = _fetch_text(self.TLD_URL, _http_timeout(ctx), ctx, self.slug)
            rows: list[str] = []
            if payload:
                for line in payload.splitlines():
                    candidate = line.strip().lower()
                    if not candidate or candidate.startswith("#") or "." in candidate:
                        continue
                    rows.append(candidate)
                ordered = [tld for tld in self.PRIORITY_TLDS if tld in rows]
                ordered.extend([tld for tld in rows if tld not in ordered and not tld.endswith("arpa")])
                self.__class__._tld_cache = ordered
            else:
                self.__class__._tld_cache = list(self.PRIORITY_TLDS)
        return list(self.__class__._tld_cache or [])

    def _events_from_variants(
        self,
        resolved: dict[str, bool],
        parent_event: ScanEvent,
        ctx,
        *,
        active_only: bool = False,
        skip_wildcards: bool = False,
    ) -> list[ScanEvent]:
        events: list[ScanEvent] = []
        root = _root_host(ctx, parent_event)
        seen: set[str] = set()
        for domain in sorted(resolved):
            if not resolved[domain] or domain in seen:
                continue
            seen.add(domain)
            if _matches_target_or_parent(domain, root):
                continue
            if skip_wildcards:
                _, _, tld = domain.partition(".")
                if tld and self._has_wildcard_tld(tld):
                    continue
            if active_only:
                page = _fetch_text(f"http://{domain}", 5, ctx, self.slug, accept="text/html, */*")
                if not page:
                    continue
            events.append(_make_event(
                event_type="similardomain",
                value=domain,
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=10,
                confidence=76,
                tags=["dns", "tld", "similar_domain"],
                raw_payload={"spiderfoot_parity": True},
            ))
        return events


class VoipBlModule(BaseModule):
    slug = "voipbl"
    name = "VoIP Blacklist (VoIPBL)"
    watched_types = {"ip", "affiliate_ipaddr", "netblock_ownership", "netblock_member"}
    produced_types = {
        "blacklisted_ip",
        "blacklisted_affiliate_ipaddr",
        "blacklisted_subnet",
        "blacklisted_netblock",
        "malicious_ip",
        "malicious_affiliate_ipaddr",
        "malicious_subnet",
        "malicious_netblock",
    }
    requires_key = False

    FEED_URL = "https://voipbl.org/update"
    _feed_cache_content: str | None = None
    _feed_cache_expires_at: datetime | None = None

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        if event.event_type == "affiliate_ipaddr" and not _module_bool(
            ctx, self.slug, _cti_slug(self.slug), ("checkaffiliates", "check_affiliates"), True
        ):
            return
        if event.event_type == "netblock_ownership" and not _module_bool(
            ctx, self.slug, _cti_slug(self.slug), ("checknetblocks", "check_netblocks"), True
        ):
            return
        if event.event_type == "netblock_member" and not _module_bool(
            ctx, self.slug, _cti_slug(self.slug), ("checksubnets", "check_subnets"), True
        ):
            return

        cache_hours = max(1, _module_int(ctx, self.slug, _cti_slug(self.slug), ("cache_hours", "cacheperiod"), 18))
        content = self._feed_content(ctx, cache_hours)
        if not content:
            return
        for child in self._events_from_feed(content, parent_event=event, ctx=ctx):
            yield child

    def _feed_content(self, ctx, cache_hours: int) -> str | None:
        now = datetime.now(timezone.utc)
        if (
            self.__class__._feed_cache_content
            and self.__class__._feed_cache_expires_at is not None
            and self.__class__._feed_cache_expires_at > now
        ):
            return self.__class__._feed_cache_content

        content = _fetch_text(self.FEED_URL, _http_timeout(ctx, 25), ctx, self.slug)
        if not content:
            return None

        self.__class__._feed_cache_content = content
        self.__class__._feed_cache_expires_at = now + timedelta(hours=cache_hours)
        return content

    def _events_from_feed(self, content: str, *, parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        indicator = str(parent_event.value or "").strip()
        if not indicator:
            return []

        matched_entry = ""
        if parent_event.event_type in {"ip", "affiliate_ipaddr"}:
            if not _valid_ip(indicator):
                return []
            ip_value = ipaddress.ip_address(indicator)
            for line in content.splitlines():
                candidate = line.strip()
                if not candidate or candidate.startswith("#"):
                    continue
                try:
                    network = ipaddress.ip_network(candidate, strict=False)
                except ValueError:
                    continue
                if ip_value in network:
                    matched_entry = candidate
                    break
        else:
            try:
                target_network = ipaddress.ip_network(indicator, strict=False)
            except ValueError:
                return []
            for line in content.splitlines():
                candidate = line.strip()
                if not candidate or candidate.startswith("#"):
                    continue
                try:
                    listed_network = ipaddress.ip_network(candidate, strict=False)
                except ValueError:
                    continue
                if listed_network.subnet_of(target_network) or listed_network.overlaps(target_network):
                    matched_entry = candidate
                    break

        if not matched_entry:
            return []

        check_url = f"https://voipbl.org/check/?ip={indicator}"
        value = f"VoIP Blacklist (VoIPBL) [{indicator}]\n<SFURL>{check_url}</SFURL>"
        return _emit_malicious_and_blacklisted(
            parent_event=parent_event,
            ctx=ctx,
            slug=self.slug,
            value=value,
            source_url=check_url,
            tags=["voipbl", "blocklist", "voip"],
            risk_score=80,
            confidence=88,
        )


__all__ = [
    "AhmiaModule",
    "DnsBruteforceModule",
    "DnsRawModule",
    "DnsGrepModule",
    "DuckDuckGoModule",
    "GrepAppModule",
    "SearchcodeModule",
    "SslAnalyzerModule",
    "TldSearcherModule",
    "VoipBlModule",
]
