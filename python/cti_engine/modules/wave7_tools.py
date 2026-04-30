"""Wave 7 no-key local scanner and web fingerprint modules for the CTI engine."""

from __future__ import annotations

import json
import re
import socket
import ssl
import subprocess
import urllib.parse
from shutil import which
from typing import Any, AsyncIterator

from ..events import ScanEvent
from ..module_base import BaseModule
from .no_key_reputation import (
    _cti_slug,
    _hostname,
    _http_timeout,
    _make_event,
    _module_int,
    _module_setting,
)
from .wave4_discovery import _fetch_http
from .wave6_reputation import _default_urls_for_target


COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    587: "SMTP Submission",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP Proxy",
    8443: "HTTPS Alt",
}

WAF_SIGNATURES = {
    "cloudflare": "Cloudflare",
    "cf-ray": "Cloudflare",
    "x-sucuri": "Sucuri",
    "x-iinfo": "Imperva Incapsula",
    "incap_ses": "Imperva Incapsula",
    "akamai": "Akamai",
    "x-akamai": "Akamai",
    "x-waf": "Generic WAF",
    "x-cdn": "CDN/WAF",
    "barracuda": "Barracuda",
}

TECH_HEADER_PATTERNS = [
    ("server", re.compile(r"apache", re.I), "Apache", "Web Server"),
    ("server", re.compile(r"nginx", re.I), "nginx", "Web Server"),
    ("server", re.compile(r"microsoft-iis", re.I), "Microsoft IIS", "Web Server"),
    ("server", re.compile(r"cloudflare", re.I), "Cloudflare", "CDN"),
    ("x-powered-by", re.compile(r"php", re.I), "PHP", "Language"),
    ("x-powered-by", re.compile(r"asp\.net", re.I), "ASP.NET", "Framework"),
    ("x-powered-by", re.compile(r"express", re.I), "Express.js", "Framework"),
]

TECH_BODY_PATTERNS = [
    (re.compile(r"wp-content|wp-includes", re.I), "WordPress", "CMS"),
    (re.compile(r"joomla", re.I), "Joomla", "CMS"),
    (re.compile(r"drupal", re.I), "Drupal", "CMS"),
    (re.compile(r"jquery", re.I), "jQuery", "JavaScript Library"),
    (re.compile(r"react", re.I), "React", "JavaScript Framework"),
    (re.compile(r"vue", re.I), "Vue.js", "JavaScript Framework"),
    (re.compile(r"bootstrap", re.I), "Bootstrap", "CSS Framework"),
    (re.compile(r"google-analytics|gtag", re.I), "Google Analytics", "Analytics"),
]

SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})"),
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
]

NUCLEI_BASIC_PROBES = {
    "/.git/config": "exposed-git-config",
    "/.env": "exposed-env-file",
    "/wp-json/": "wordpress-rest-api",
    "/phpinfo.php": "phpinfo-exposure",
}


def _target_host(event: ScanEvent) -> str:
    host = _hostname(event.value)
    return host or str(event.value or "").strip()


def _tool_path(ctx, slug: str, default_name: str) -> str | None:
    configured = str(_module_setting(ctx, slug, _cti_slug(slug), ("tool_path", "path", f"{slug}_path"), "") or "").strip()
    if configured:
        return configured
    return which(default_name)


def _run_tool(args: list[str], timeout: int, ctx, slug: str) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except Exception as exc:
        ctx.warning(f"{slug} could not run: {exc}", slug)
        return None


def _tool_event(
    *,
    module: str,
    event_type: str,
    value: str,
    parent_event: ScanEvent,
    ctx,
    risk_score: int = 10,
    confidence: int = 75,
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


def _parse_port_list(value: Any, default: list[int]) -> list[int]:
    if isinstance(value, (list, tuple, set)):
        raw_items = list(value)
    else:
        raw_items = re.split(r"[\s,]+", str(value or "")) if value else []
    ports: list[int] = []
    for item in raw_items:
        try:
            port = int(str(item).strip())
        except Exception:
            continue
        if 1 <= port <= 65535 and port not in ports:
            ports.append(port)
    return ports or list(default)


def _scan_open_ports(host: str, ports: list[int], timeout: float) -> list[tuple[int, str]]:
    open_ports: list[tuple[int, str]] = []
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                open_ports.append((port, COMMON_PORTS.get(port, f"tcp/{port}")))
        except Exception:
            continue
    return open_ports


def _headers_to_text(headers: dict[str, str]) -> str:
    return "\n".join(f"{key}: {value}" for key, value in sorted(headers.items()))


class NbtscanModule(BaseModule):
    slug = "nbtscan"
    name = "NBTScan"
    watched_types = {"ip", "netblock_member"}
    produced_types = {"netbios_name", "raw_netbios_data"}
    requires_key = False

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        executable = _tool_path(ctx, self.slug, "nbtscan")
        if not executable:
            ctx.warning("nbtscan is enabled but the nbtscan executable was not found.", self.slug)
            return
        completed = _run_tool([executable, event.value], max(10, _http_timeout(ctx)), ctx, self.slug)
        if not completed or completed.returncode != 0:
            return
        for child in self._events_from_output(completed.stdout, event, ctx):
            yield child

    def _events_from_output(self, output: str, parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        events = []
        for line in output.splitlines():
            row = line.strip()
            if not row or row.lower().startswith("ip address"):
                continue
            parts = row.split()
            if len(parts) >= 2:
                events.append(_tool_event(
                    module=self.slug,
                    event_type="netbios_name",
                    value=parts[1],
                    parent_event=parent_event,
                    ctx=ctx,
                    raw_payload={"line": row, "spiderfoot_parity": True},
                ))
        return events


class NmapModule(BaseModule):
    slug = "nmap"
    name = "Nmap"
    watched_types = {"domain", "internet_name", "ip"}
    produced_types = {"open_tcp_port", "internet_service"}
    requires_key = False

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        host = _target_host(event)
        ports = _parse_port_list(
            _module_setting(ctx, self.slug, _cti_slug(self.slug), ("ports", "tcp_ports"), ""),
            [22, 80, 443],
        )
        executable = _tool_path(ctx, self.slug, "nmap")
        if executable:
            completed = _run_tool([executable, "-oX", "-", "-Pn", "-p", ",".join(map(str, ports)), host], max(20, _http_timeout(ctx) * 3), ctx, self.slug)
            if completed and completed.returncode == 0:
                for child in self._events_from_nmap_output(completed.stdout, event, ctx):
                    yield child
                return
        for port, service in _scan_open_ports(host, ports, min(3.0, float(_module_int(ctx, self.slug, _cti_slug(self.slug), "connect_timeout", 2)))):
            yield _tool_event(
                module=self.slug,
                event_type="open_tcp_port",
                value=f"{host}:{port} ({service})",
                parent_event=event,
                ctx=ctx,
                risk_score=20,
                tags=[self.slug, "port_scan"],
                raw_payload={"host": host, "port": port, "service": service, "spiderfoot_parity": True},
            )

    def _events_from_nmap_output(self, output: str, parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        events = []
        for port, service in re.findall(r'portid="(\d+)".*?<state state="open".*?<service name="([^"]+)"', output, re.S):
            events.append(_tool_event(
                module=self.slug,
                event_type="open_tcp_port",
                value=f"{_target_host(parent_event)}:{port} ({service})",
                parent_event=parent_event,
                ctx=ctx,
                risk_score=20,
                tags=[self.slug, "nmap"],
                raw_payload={"port": int(port), "service": service, "spiderfoot_parity": True},
            ))
        return events


class NucleiModule(BaseModule):
    slug = "nuclei"
    name = "Nuclei"
    watched_types = {"domain", "url", "internet_name"}
    produced_types = {"vulnerability", "exposed_file"}
    requires_key = False

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        executable = _tool_path(ctx, self.slug, "nuclei")
        target = _default_urls_for_target(event)[0] if _default_urls_for_target(event) else event.value
        if executable:
            completed = _run_tool([executable, "-jsonl", "-silent", "-u", target], max(30, _http_timeout(ctx) * 4), ctx, self.slug)
            if completed and completed.returncode == 0:
                for child in self._events_from_jsonl(completed.stdout, event, ctx):
                    yield child
                return
        for child in self._basic_probe_events(target, event, ctx):
            yield child

    def _events_from_jsonl(self, output: str, parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        events = []
        for line in output.splitlines():
            try:
                row = json.loads(line)
            except Exception:
                continue
            template_id = row.get("template-id") or row.get("templateID") or "nuclei-finding"
            matched = row.get("matched-at") or row.get("host") or parent_event.value
            severity = str(row.get("info", {}).get("severity", "info")).lower() if isinstance(row.get("info"), dict) else "info"
            risk = {"critical": 90, "high": 75, "medium": 50, "low": 25, "info": 5}.get(severity, 20)
            events.append(_tool_event(
                module=self.slug,
                event_type="vulnerability",
                value=f"{template_id}: {matched}",
                parent_event=parent_event,
                ctx=ctx,
                risk_score=risk,
                tags=[self.slug, "nuclei", severity],
                raw_payload={"finding": row, "spiderfoot_parity": True},
            ))
        return events

    def _basic_probe_events(self, target_url: str, parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        base = str(target_url or "").rstrip("/")
        events = []
        for path, finding in NUCLEI_BASIC_PROBES.items():
            status, body, final_url, _ = _fetch_http(base + path, _http_timeout(ctx), ctx, self.slug, max_bytes=80_000)
            if status == 200 and body:
                events.append(_tool_event(
                    module=self.slug,
                    event_type="vulnerability",
                    value=f"{finding}: {final_url}",
                    parent_event=parent_event,
                    ctx=ctx,
                    risk_score=50,
                    tags=[self.slug, "basic_probe"],
                    raw_payload={"url": final_url, "spiderfoot_parity": True},
                ))
        return events


class OneSixtyOneModule(BaseModule):
    slug = "onesixtyone"
    name = "onesixtyone"
    watched_types = {"ip"}
    produced_types = {"snmp_info"}
    requires_key = False

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        executable = _tool_path(ctx, self.slug, "onesixtyone")
        if not executable:
            ctx.warning("onesixtyone is enabled but the executable was not found.", self.slug)
            return
        community = str(_module_setting(ctx, self.slug, _cti_slug(self.slug), "community", "public") or "public")
        completed = _run_tool([executable, "-c", community, event.value], max(10, _http_timeout(ctx)), ctx, self.slug)
        if not completed or completed.returncode != 0:
            return
        for line in completed.stdout.splitlines():
            row = line.strip()
            if row:
                yield _tool_event(
                    module=self.slug,
                    event_type="snmp_info",
                    value=row,
                    parent_event=event,
                    ctx=ctx,
                    risk_score=45,
                    tags=[self.slug, "snmp"],
                    raw_payload={"spiderfoot_parity": True},
                )


class PortScannerTcpModule(NmapModule):
    slug = "port-scanner-tcp"
    name = "TCP Port Scanner"


class TestSslModule(BaseModule):
    slug = "testssl"
    name = "testssl.sh"
    watched_types = {"domain", "internet_name", "url"}
    produced_types = {"ssl_certificate", "ssl_cipher"}
    requires_key = False

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        host = _target_host(event)
        port = 443
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=min(5, _http_timeout(ctx))) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                    cert = tls_sock.getpeercert()
                    cipher = tls_sock.cipher()
        except Exception as exc:
            ctx.warning(f"testssl TLS check failed: {exc}", self.slug)
            return
        subject = ", ".join("=".join(item) for part in cert.get("subject", []) for item in part)
        issuer = ", ".join("=".join(item) for part in cert.get("issuer", []) for item in part)
        yield _tool_event(
            module=self.slug,
            event_type="ssl_certificate",
            value=f"{host}: subject {subject or 'unknown'}, issuer {issuer or 'unknown'}",
            parent_event=event,
            ctx=ctx,
            tags=[self.slug, "tls"],
            raw_payload={"certificate": cert, "spiderfoot_parity": True},
        )
        if cipher:
            yield _tool_event(
                module=self.slug,
                event_type="ssl_cipher",
                value=f"{host}: {cipher[0]} {cipher[1]}",
                parent_event=event,
                ctx=ctx,
                tags=[self.slug, "tls"],
                raw_payload={"cipher": cipher, "spiderfoot_parity": True},
            )


class TruffleHogModule(BaseModule):
    slug = "trufflehog"
    name = "TruffleHog"
    watched_types = {"domain", "url", "internet_name", "target_web_content", "linked_url_internal"}
    produced_types = {"secret_leak"}
    requires_key = False

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        contents: list[tuple[str, str]] = []
        if event.event_type == "target_web_content":
            contents.append((str(event.raw_payload.get("source_url") or ctx.root_target), event.value))
        else:
            for url in _default_urls_for_target(event):
                status, body, final_url, _ = _fetch_http(url, _http_timeout(ctx), ctx, self.slug, max_bytes=1_000_000)
                if status == 200 and body:
                    contents.append((final_url, body))
        for source_url, body in contents:
            for child in self._events_from_content(body, source_url, event, ctx):
                yield child

    def _events_from_content(self, content: str, source_url: str, parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        events = []
        seen: set[str] = set()
        for pattern in SECRET_PATTERNS:
            for match in pattern.finditer(content):
                value = match.group(0)[:120]
                if value in seen:
                    continue
                seen.add(value)
                events.append(_tool_event(
                    module=self.slug,
                    event_type="secret_leak",
                    value=f"Potential secret in {source_url}: {value}",
                    parent_event=parent_event,
                    ctx=ctx,
                    risk_score=80,
                    confidence=70,
                    tags=[self.slug, "secret"],
                    raw_payload={"source_url": source_url, "spiderfoot_parity": True},
                ))
        return events


class Wafw00fModule(BaseModule):
    slug = "wafw00f"
    name = "WAFW00F"
    watched_types = {"domain", "url", "internet_name"}
    produced_types = {"web_application_firewall"}
    requires_key = False

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        for url in _default_urls_for_target(event):
            status, body, final_url, headers = _fetch_http(url, _http_timeout(ctx), ctx, self.slug, accept="text/html, */*", max_bytes=250_000)
            if status:
                for child in self._events_from_response(status, body, final_url, headers, event, ctx):
                    yield child
                return

    def _events_from_response(self, status: int, body: str, url: str, headers: dict[str, str], parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        haystack = (_headers_to_text(headers) + "\n" + body[:5000]).lower()
        detections = []
        for marker, name in WAF_SIGNATURES.items():
            if marker in haystack and name not in detections:
                detections.append(name)
        if status in {403, 406, 429} and not detections:
            detections.append("Possible WAF")
        return [
            _tool_event(
                module=self.slug,
                event_type="web_application_firewall",
                value=f"{url}: {name}",
                parent_event=parent_event,
                ctx=ctx,
                risk_score=10,
                confidence=70,
                tags=[self.slug, "waf"],
                raw_payload={"status": status, "headers": headers, "spiderfoot_parity": True},
            )
            for name in detections
        ]


class WappalyzerModule(BaseModule):
    slug = "wappalyzer"
    name = "Wappalyzer"
    watched_types = {"domain", "url", "internet_name", "target_web_content"}
    produced_types = {"software_used"}
    requires_key = False

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        responses = []
        if event.event_type == "target_web_content":
            responses.append((str(event.raw_payload.get("source_url") or ctx.root_target), event.value, {}))
        else:
            for url in _default_urls_for_target(event):
                status, body, final_url, headers = _fetch_http(url, _http_timeout(ctx), ctx, self.slug, accept="text/html, */*", max_bytes=1_000_000)
                if status == 200:
                    responses.append((final_url, body, headers))
                    break
        for final_url, body, headers in responses:
            for child in self._events_from_response(body, headers, final_url, event, ctx):
                yield child

    def _events_from_response(self, body: str, headers: dict[str, str], source_url: str, parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        found: dict[str, str] = {}
        lower_headers = {str(k).lower(): str(v) for k, v in headers.items()}
        for header, pattern, name, category in TECH_HEADER_PATTERNS:
            if pattern.search(lower_headers.get(header, "")):
                found[name] = category
        for pattern, name, category in TECH_BODY_PATTERNS:
            if pattern.search(body):
                found[name] = category
        return [
            _tool_event(
                module=self.slug,
                event_type="software_used",
                value=f"{name} ({category})",
                parent_event=parent_event,
                ctx=ctx,
                risk_score=5,
                confidence=75,
                tags=[self.slug, "technology", category.lower().replace(" ", "_")],
                raw_payload={"source_url": source_url, "spiderfoot_parity": True},
            )
            for name, category in sorted(found.items())
        ]


class WhatWebModule(WappalyzerModule):
    slug = "whatweb"
    name = "WhatWeb"
    produced_types = {"software_used", "raw_web_header"}

    def _events_from_response(self, body: str, headers: dict[str, str], source_url: str, parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        events = super()._events_from_response(body, headers, source_url, parent_event, ctx)
        server = headers.get("server") or headers.get("Server")
        powered = headers.get("x-powered-by") or headers.get("X-Powered-By")
        title_match = re.search(r"<title[^>]*>([^<]+)", body, re.I)
        parts = [f"URL: {source_url}"]
        if server:
            parts.append(f"Server: {server}")
        if powered:
            parts.append(f"Powered-By: {powered}")
        if title_match:
            parts.append(f"Title: {title_match.group(1).strip()[:80]}")
        events.append(_tool_event(
            module=self.slug,
            event_type="raw_web_header",
            value="; ".join(parts),
            parent_event=parent_event,
            ctx=ctx,
            risk_score=5,
            confidence=80,
            tags=[self.slug, "web_info"],
            raw_payload={"headers": headers, "source_url": source_url, "spiderfoot_parity": True},
        ))
        return events


__all__ = [
    "NbtscanModule",
    "NmapModule",
    "NucleiModule",
    "OneSixtyOneModule",
    "PortScannerTcpModule",
    "TestSslModule",
    "TruffleHogModule",
    "Wafw00fModule",
    "WappalyzerModule",
    "WhatWebModule",
]
