"""Wave 6 no-key threat, reputation, and feed modules for the CTI engine."""

from __future__ import annotations

import json
import re
import urllib.parse
from typing import Any, AsyncIterator

from ..events import ScanEvent
from ..module_base import BaseModule
from .no_key_reputation import (
    _cti_slug,
    DnsblModule,
    _event_pair_for,
    _fetch_text,
    _hostname,
    _http_timeout,
    _make_event,
    _module_setting,
    _reverse_ipv4,
)
from .wave4_discovery import _fetch_http
from .wave5_extractors import _seed_urls_for_event


RISKY_FORTIGUARD_CATEGORIES = {
    "malicious websites",
    "phishing",
    "spam urls",
    "newly observed domain",
    "newly registered domain",
    "hacking",
    "proxy avoidance",
    "command and control",
    "botnet",
    "malware",
    "crypto mining",
}

RETIRE_PATTERNS = [
    {
        "library": "jQuery",
        "pattern": re.compile(r"jquery[.\-/]?(1\.\d+\.\d+|2\.\d+\.\d+|3\.[0-4]\.\d+)", re.I),
        "fixed": "3.5.0",
        "severity": "medium",
        "cve": "CVE-2020-11022, CVE-2020-11023",
    },
    {
        "library": "AngularJS",
        "pattern": re.compile(r"angular[.\-/]?(1\.[0-7]\.\d+)", re.I),
        "fixed": "1.8.0",
        "severity": "high",
        "cve": "CVE-2019-10768, CVE-2020-7676",
    },
    {
        "library": "Bootstrap",
        "pattern": re.compile(r"bootstrap[.\-/]?(3\.\d+\.\d+|4\.[0-4]\.\d+)", re.I),
        "fixed": "4.5.0",
        "severity": "medium",
        "cve": "CVE-2019-8331",
    },
    {
        "library": "Lodash",
        "pattern": re.compile(r"lodash[.\-/]?(3\.\d+\.\d+|4\.\d+\.\d+)", re.I),
        "fixed": "4.17.21",
        "severity": "high",
        "cve": "CVE-2021-23337, CVE-2020-8203",
    },
]

SNALLYGASTER_PROBES = {
    "/.git/HEAD": ("critical", "Git repository HEAD", "ref:"),
    "/.env": ("critical", "Environment config", "="),
    "/wp-config.php": ("critical", "WordPress config", "DB_"),
    "/phpinfo.php": ("high", "PHP info page", "phpinfo"),
    "/server-status": ("high", "Apache server status", "Apache"),
    "/backup.zip": ("critical", "Backup archive", None),
    "/composer.json": ("medium", "Composer manifest", "require"),
    "/package.json": ("medium", "Node package manifest", None),
    "/robots.txt": ("info", "Robots file", None),
    "/.well-known/security.txt": ("info", "Security contact file", "Contact"),
}


def _json_payload(text: str | None) -> Any:
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        return None


def _indicator_value(event: ScanEvent) -> str:
    return str(event.value or "").strip()


def _query_url(value: str, field: str) -> str:
    return urllib.parse.quote(str(value or ""), safe="" if field != "url" else ":/?&=%#[]@!$'()*+,;")


def _default_urls_for_target(event: ScanEvent) -> list[str]:
    urls = _seed_urls_for_event(event)
    if urls:
        return urls
    host = _hostname(event.value)
    return [f"https://{host}", f"http://{host}"] if host else []


def _event_for_reputation(
    *,
    module: str,
    event_type: str,
    value: str,
    parent_event: ScanEvent,
    ctx,
    risk_score: int = 40,
    confidence: int = 70,
    tags: list[str] | None = None,
    raw_payload: dict[str, Any] | None = None,
) -> ScanEvent:
    return _make_event(
        event_type=event_type,
        value=value,
        slug=module,
        parent_event=parent_event,
        ctx=ctx,
        risk_score=risk_score,
        confidence=confidence,
        tags=tags or [module],
        raw_payload=raw_payload or {"spiderfoot_parity": True},
    )


class AlienVaultIpRepModule(BaseModule):
    slug = "alienvault-ip-rep"
    name = "AlienVault IP Reputation"
    watched_types = {"ip"}
    produced_types = {"malicious_ip", "raw_reputation"}
    requires_key = False

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        endpoint = (
            "https://otx.alienvault.com/api/v1/indicators/IPv4/"
            f"{urllib.parse.quote(event.value)}/reputation"
        )
        content = _fetch_text(endpoint, _http_timeout(ctx), ctx, self.slug, accept="application/json")
        payload = _json_payload(content)
        if not isinstance(payload, dict):
            return
        events = self._events_from_payload(payload, event, ctx)
        for child in events:
            yield child

    def _events_from_payload(self, payload: dict[str, Any], parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        reputation = payload.get("reputation", payload.get("data", 0)) or 0
        try:
            score = int(reputation)
        except Exception:
            score = 0
        details = payload.get("reputation_details") or []
        activity_count = len(details) if isinstance(details, list) else 0
        if score <= 0 and activity_count <= 0:
            return []
        risk = min(95, max(55, score * 10 + activity_count * 5))
        label = f"AlienVault IP reputation for {parent_event.value}: score {score}, activities {activity_count}"
        return [
            _event_for_reputation(
                module=self.slug,
                event_type="malicious_ip",
                value=label,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=risk,
                confidence=80,
                tags=[self.slug, "reputation", "malicious"],
                raw_payload={"reputation": score, "activity_count": activity_count, "spiderfoot_parity": True},
            )
        ]


class CleanTalkModule(BaseModule):
    slug = "cleantalk"
    name = "CleanTalk"
    watched_types = {"domain", "internet_name", "ip", "email"}
    produced_types = {"blacklisted_ip", "blacklisted_email", "blacklisted_internet_name"}
    requires_key = False

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        value = _indicator_value(event)
        if not value:
            return
        field = "ip" if event.event_type == "ip" else "email"
        query = value if field == "ip" else (value if "@" in value else f"test@{_hostname(value) or value}")
        endpoint = f"https://api.cleantalk.org/?method_name=spam_check&auth_key=&{field}={urllib.parse.quote(query)}"
        content = _fetch_text(endpoint, _http_timeout(ctx), ctx, self.slug, accept="application/json")
        payload = _json_payload(content)
        if not isinstance(payload, dict):
            return
        for child in self._events_from_payload(payload, event, ctx):
            yield child

    def _events_from_payload(self, payload: dict[str, Any], parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        data = payload.get("data", payload)
        entry = None
        if isinstance(data, dict):
            for candidate in data.values():
                if isinstance(candidate, dict):
                    entry = candidate
                    break
        if not entry:
            return []
        appears = int(entry.get("appears") or 0)
        frequency = int(entry.get("frequency") or 0)
        if appears <= 0:
            return []
        _, blacklisted_type = _event_pair_for(parent_event.event_type)
        return [
            _event_for_reputation(
                module=self.slug,
                event_type=blacklisted_type,
                value=f"CleanTalk spam listing for {parent_event.value}: appearances {appears}, frequency {frequency}",
                parent_event=parent_event,
                ctx=ctx,
                risk_score=min(85, 35 + frequency),
                confidence=75,
                tags=[self.slug, "spam", "blacklisted"],
                raw_payload={"appears": appears, "frequency": frequency, "spiderfoot_parity": True},
            )
        ]


class CustomThreatFeedModule(BaseModule):
    slug = "custom-threat-feed"
    name = "Custom Threat Feed"
    watched_types = {"domain", "internet_name", "ip", "url", "hash"}
    produced_types = {"malicious_indicator", "blacklisted_indicator"}
    requires_key = False

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        feed_urls = _module_setting(ctx, self.slug, _cti_slug(self.slug), ("feed_urls", "feed_url", "url"), "")
        if isinstance(feed_urls, str):
            urls = [item.strip() for item in re.split(r"[\r\n,]+", feed_urls) if item.strip()]
        else:
            urls = [str(item or "").strip() for item in feed_urls if str(item or "").strip()]
        if not urls:
            ctx.warning("custom-threat-feed is enabled but no feed URL is configured.", self.slug)
            return
        target = _indicator_value(event).lower()
        for url in urls:
            content = _fetch_text(url, _http_timeout(ctx), ctx, self.slug)
            if not content:
                continue
            for child in self._events_from_content(content, url, target, event, ctx):
                yield child

    def _events_from_content(self, content: str, source_url: str, target: str, parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        for line in content.splitlines():
            row = line.strip()
            if not row or row.startswith("#"):
                continue
            if target and target in row.lower():
                return [
                    _event_for_reputation(
                        module=self.slug,
                        event_type="blacklisted_indicator",
                        value=f"Custom threat feed match [{parent_event.value}]\n<SFURL>{source_url}</SFURL>",
                        parent_event=parent_event,
                        ctx=ctx,
                        risk_score=80,
                        confidence=80,
                        tags=[self.slug, "feed", "blacklisted"],
                        raw_payload={"source_url": source_url, "line": row[:500], "spiderfoot_parity": True},
                    )
                ]
        return []


class FortiGuardModule(BaseModule):
    slug = "fortiguard"
    name = "FortiGuard"
    watched_types = {"domain", "internet_name", "ip", "url"}
    produced_types = {"web_site_categorization", "malicious_indicator"}
    requires_key = False

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        endpoint = "https://www.fortiguard.com/webfilter?q=" + urllib.parse.quote(_indicator_value(event))
        status, body, final_url, _ = _fetch_http(
            endpoint,
            _http_timeout(ctx),
            ctx,
            self.slug,
            accept="text/html, */*",
        )
        if status != 200 or not body:
            return
        for child in self._events_from_body(body, final_url, event, ctx):
            yield child

    def _events_from_body(self, body: str, source_url: str, parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        category = "Unknown"
        patterns = [
            r"Category:\s*([^<\n]+)",
            r"<h4[^>]*class=[\"'][^\"']*cat[^\"']*[\"'][^>]*>([^<]+)",
            r"<meta[^>]+property=[\"']og:description[\"'][^>]+content=[\"']([^\"']+)",
        ]
        for pattern in patterns:
            match = re.search(pattern, body, re.I)
            if match:
                category = re.sub(r"\s+", " ", match.group(1)).strip()
                break
        if not category or category == "Unknown":
            return []
        risky = any(item in category.lower() for item in RISKY_FORTIGUARD_CATEGORIES)
        return [
            _event_for_reputation(
                module=self.slug,
                event_type="web_site_categorization",
                value=f"{parent_event.value}: {category}",
                parent_event=parent_event,
                ctx=ctx,
                risk_score=65 if risky else 5,
                confidence=70,
                tags=[self.slug, "web_filter"] + (["risky_category"] if risky else ["category"]),
                raw_payload={"category": category, "source_url": source_url, "spiderfoot_parity": True},
            )
        ]


class MalwarePatrolModule(CustomThreatFeedModule):
    slug = "malwarepatrol"
    name = "Malware Patrol"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        list_url = str(_module_setting(ctx, self.slug, _cti_slug(self.slug), ("list_url", "feed_url"), "") or "").strip()
        receipt = str(_module_setting(ctx, self.slug, _cti_slug(self.slug), ("receipt", "api_key"), "") or "").strip()
        if not list_url and receipt:
            list_url = (
                "https://lists.malwarepatrol.net/cgi/getfile?"
                f"receipt={urllib.parse.quote(receipt)}&product=8&list=dansguardian"
            )
        if not list_url:
            ctx.warning("malwarepatrol is enabled but no list URL or receipt is configured.", self.slug)
            return
        content = _fetch_text(list_url, _http_timeout(ctx, 30), ctx, self.slug)
        if not content:
            return
        target = _indicator_value(event).lower()
        for child in self._events_from_content(content, list_url, target, event, ctx):
            yield child


class ScyllaModule(BaseModule):
    slug = "scylla"
    name = "Scylla"
    watched_types = {"email", "username"}
    produced_types = {"breach_record"}
    requires_key = False

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        field = "email" if event.event_type == "email" else "username"
        endpoint = f"https://scylla.sh/search?q={field}:{urllib.parse.quote(event.value)}"
        content = _fetch_text(endpoint, _http_timeout(ctx), ctx, self.slug, accept="application/json")
        payload = _json_payload(content)
        for child in self._events_from_payload(payload, event, ctx):
            yield child

    def _events_from_payload(self, payload: Any, parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        if not payload:
            return []
        rows = payload if isinstance(payload, list) else payload.get("data", []) if isinstance(payload, dict) else []
        if not isinstance(rows, list) or not rows:
            return []
        sources: list[str] = []
        for row in rows[:20]:
            if isinstance(row, dict):
                source = row.get("domain") or row.get("source") or row.get("database") or "unknown"
                if source not in sources:
                    sources.append(str(source))
        return [
            _event_for_reputation(
                module=self.slug,
                event_type="breach_record",
                value=f"{parent_event.value}: found in {len(rows)} breach record(s)",
                parent_event=parent_event,
                ctx=ctx,
                risk_score=min(90, 50 + len(rows) * 3),
                confidence=75,
                tags=[self.slug, "breach", "leaked"],
                raw_payload={"count": len(rows), "sources": sources, "spiderfoot_parity": True},
            )
        ]


class SorbsModule(DnsblModule):
    slug = "sorbs"
    name = "SORBS"
    watched_types = {"ip", "affiliate_ipaddr", "netblock_ownership", "netblock_member"}
    produced_types = {"blacklisted_ip", "malicious_ip"}
    requires_key = False

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        reversed_ip = _reverse_ipv4(event.value)
        if not reversed_ip:
            return
        lookup = f"{reversed_ip}.dnsbl.sorbs.net"
        for result in self._resolve(lookup):
            value = f"SORBS DNSBL [{event.value}]"
            for child in self._dnsbl_events(
                parent_event=event,
                ctx=ctx,
                value=value,
                source_url="https://www.sorbs.net/",
                result_label=result,
            ):
                yield child


class TalosIntelligenceModule(BaseModule):
    slug = "talos-intelligence"
    name = "Talos Intelligence"
    watched_types = {"domain", "internet_name", "ip"}
    produced_types = {"web_site_categorization", "malicious_indicator"}
    requires_key = False

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        query_path = "%2Fapi%2Fv2%2Fdetails%2Fip%2F" if event.event_type == "ip" else "%2Fapi%2Fv2%2Fdetails%2Fdomain%2F"
        endpoint = (
            "https://talosintelligence.com/sb_api/query_lookup?"
            f"query={query_path}&query_entry={urllib.parse.quote(event.value)}"
        )
        content = _fetch_text(endpoint, _http_timeout(ctx), ctx, self.slug, accept="application/json")
        payload = _json_payload(content)
        if isinstance(payload, dict):
            for child in self._events_from_payload(payload, event, ctx):
                yield child

    def _events_from_payload(self, payload: dict[str, Any], parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        reputation = str(payload.get("reputation") or payload.get("web_score_name") or payload.get("email_score_name") or "unknown").strip()
        category = payload.get("category") or ""
        category_text = ", ".join(category) if isinstance(category, list) else str(category or "")
        risky = reputation.lower() in {"poor", "bad", "untrusted", "questionable", "suspicious"}
        value = f"{parent_event.value}: Talos reputation {reputation}"
        if category_text:
            value += f", category {category_text}"
        return [
            _event_for_reputation(
                module=self.slug,
                event_type="web_site_categorization",
                value=value,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=65 if risky else 10,
                confidence=75 if reputation != "unknown" else 45,
                tags=[self.slug, "reputation"] + (["suspicious"] if risky else ["category"]),
                raw_payload={"reputation": reputation, "category": category_text, "spiderfoot_parity": True},
            )
        ]


class RetireJsModule(BaseModule):
    slug = "retire-js"
    name = "Retire.js"
    watched_types = {"domain", "url", "internet_name", "linked_url_internal"}
    produced_types = {"vulnerable_javascript_library"}
    requires_key = False

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        for url in _default_urls_for_target(event):
            status, body, final_url, _ = _fetch_http(url, _http_timeout(ctx), ctx, self.slug, accept="text/html, */*", max_bytes=1_000_000)
            if status == 200 and body:
                for child in self._events_from_content(body, final_url, event, ctx):
                    yield child

    def _events_from_content(self, content: str, source_url: str, parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        events = []
        seen: set[str] = set()
        for rule in RETIRE_PATTERNS:
            match = rule["pattern"].search(content)
            if not match:
                continue
            version = match.group(1)
            key = f"{rule['library']}:{version}"
            if key in seen:
                continue
            seen.add(key)
            events.append(_event_for_reputation(
                module=self.slug,
                event_type="vulnerable_javascript_library",
                value=f"{rule['library']} {version} below {rule['fixed']} ({rule['severity']})",
                parent_event=parent_event,
                ctx=ctx,
                risk_score=70 if rule["severity"] == "high" else 45,
                confidence=75,
                tags=[self.slug, "javascript", "vulnerable_library"],
                raw_payload={"source_url": source_url, "cve": rule["cve"], "spiderfoot_parity": True},
            ))
        return events


class SnallygasterModule(BaseModule):
    slug = "snallygaster"
    name = "Snallygaster"
    watched_types = {"domain", "url", "internet_name"}
    produced_types = {"exposed_file"}
    requires_key = False

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        bases = [url.rstrip("/") for url in _default_urls_for_target(event)]
        timeout = max(3, _http_timeout(ctx))
        for base_url in bases:
            for path, info in SNALLYGASTER_PROBES.items():
                probe_url = base_url + path
                status, body, final_url, _ = _fetch_http(probe_url, timeout, ctx, self.slug, max_bytes=100_000)
                if status != 200 or len(body) < 3:
                    continue
                risk, description, confirm = info
                if confirm and confirm.lower() not in body.lower():
                    continue
                risk_score = {"critical": 90, "high": 70, "medium": 45, "low": 20, "info": 5}.get(risk, 20)
                yield _event_for_reputation(
                    module=self.slug,
                    event_type="exposed_file",
                    value=f"{final_url} - {description}",
                    parent_event=event,
                    ctx=ctx,
                    risk_score=risk_score,
                    confidence=80,
                    tags=[self.slug, "exposed_file", risk],
                    raw_payload={"url": final_url, "risk": risk, "description": description, "spiderfoot_parity": True},
                )


__all__ = [
    "AlienVaultIpRepModule",
    "CleanTalkModule",
    "CustomThreatFeedModule",
    "FortiGuardModule",
    "MalwarePatrolModule",
    "ScyllaModule",
    "SorbsModule",
    "TalosIntelligenceModule",
    "RetireJsModule",
    "SnallygasterModule",
]
