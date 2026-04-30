"""Wave 4 no-key DNS, cloud discovery, and crawling modules for the CTI engine."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import http.cookiejar
import ipaddress
import json
import os
from pathlib import Path
import random
import re
from shutil import which
import socket
import ssl
import struct
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, AsyncIterator

from ..events import ScanEvent
from ..module_base import BaseModule
from .no_key_reputation import (
    USER_AGENT,
    _cti_slug,
    _fetch_text,
    _host_resolves,
    _hostname,
    _http_timeout,
    _make_event,
    _matches_root_target,
    _module_bool,
    _module_int,
    _module_setting,
    _parse_network,
    _valid_ip,
    _valid_ipv4,
)


HTML_LINK_RX = re.compile(r"""(?:href|src)=["']([^"'#]+)""", re.I)
HTML_FORM_RX = re.compile(r"<form\b", re.I)
HTML_COMMENT_RX = re.compile(r"<!--(.*?)-->", re.I | re.S)
DOMAINISH_RX = re.compile(r"([a-z0-9][a-z0-9\-_.]*\.[a-z]{2,63})", re.I)

DEFAULT_BUCKET_SUFFIXES = [
    "",
    "test",
    "dev",
    "web",
    "beta",
    "bucket",
    "space",
    "files",
    "content",
    "data",
    "prod",
    "staging",
    "production",
    "stage",
    "app",
    "media",
    "development",
    "-test",
    "-dev",
    "-web",
    "-beta",
    "-bucket",
    "-space",
    "-files",
    "-content",
    "-data",
    "-prod",
    "-staging",
    "-production",
    "-stage",
    "-app",
    "-media",
    "-development",
]

DEFAULT_DO_ENDPOINTS = [
    "nyc3.digitaloceanspaces.com",
    "sgp1.digitaloceanspaces.com",
    "ams3.digitaloceanspaces.com",
]

DEFAULT_S3_ENDPOINTS = [
    "s3.amazonaws.com",
    "s3-external-1.amazonaws.com",
    "s3-us-west-1.amazonaws.com",
    "s3-us-west-2.amazonaws.com",
    "s3.ap-south-1.amazonaws.com",
    "s3-ap-south-1.amazonaws.com",
    "s3.ap-northeast-2.amazonaws.com",
    "s3-ap-northeast-2.amazonaws.com",
    "s3-ap-southeast-1.amazonaws.com",
    "s3-ap-southeast-2.amazonaws.com",
    "s3-ap-northeast-1.amazonaws.com",
    "s3.eu-central-1.amazonaws.com",
    "s3-eu-central-1.amazonaws.com",
    "s3-eu-west-1.amazonaws.com",
    "s3-sa-east-1.amazonaws.com",
]

OPENNIC_NAMESERVERS = [
    "192.3.165.37",
    "35.211.96.150",
    "51.89.88.77",
    "94.247.43.254",
    "138.197.140.189",
]

OPENNIC_TLDS = {
    "bbs",
    "chan",
    "cyb",
    "dyn",
    "epic",
    "free",
    "geek",
    "glue",
    "gopher",
    "indy",
    "libre",
    "neo",
    "null",
    "o",
    "oss",
    "oz",
    "parody",
    "pirate",
    "bazar",
    "bit",
    "coin",
    "emc",
    "fur",
    "ku",
    "lib",
    "te",
    "ti",
    "uu",
}

S3_PATH_STYLE_HOSTS = set(DEFAULT_S3_ENDPOINTS)
MAX_WEB_CONTENT_CHARS = 100000

_DNS_TYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    252: "AXFR",
}


def _normalize_indicator(value: str) -> str:
    candidate = _hostname(value)
    if candidate:
        return candidate.strip().lower().rstrip(".")
    return str(value or "").strip().lower().rstrip(".")


def _domain_keyword(value: str) -> str:
    host = _normalize_indicator(value)
    if not host:
        return ""
    if _valid_ip(host):
        return ""
    return host.split(".", 1)[0].strip().lower()


def _split_csv(value: Any, default: list[str]) -> list[str]:
    if isinstance(value, (list, tuple, set)):
        items = [str(item or "").strip() for item in value]
    else:
        raw = str(value or "").strip()
        items = [part.strip() for part in raw.split(",")] if raw else []
    cleaned = [item for item in items if item]
    return cleaned or list(default)


def _probe_thread_count(ctx, slug: str, default: int = 20) -> int:
    return max(1, _module_int(ctx, slug, slug, ("_maxthreads", "max_threads", "maxthreads"), default))


def _fetch_http(
    url: str,
    timeout: int,
    ctx,
    slug: str,
    *,
    accept: str = "*/*",
    extra_headers: dict[str, str] | None = None,
    cookie_jar: http.cookiejar.CookieJar | None = None,
    max_bytes: int | None = None,
) -> tuple[int, str, str, dict[str, str]]:
    headers = {
        "Accept": accept,
        "User-Agent": USER_AGENT,
    }
    if extra_headers:
        headers.update(extra_headers)

    request = urllib.request.Request(url, headers=headers, method="GET")
    handlers: list[Any] = [urllib.request.HTTPSHandler(context=ssl._create_unverified_context())]
    if cookie_jar is not None:
        handlers.insert(0, urllib.request.HTTPCookieProcessor(cookie_jar))
    opener = urllib.request.build_opener(*handlers)

    ctx.info(f"Fetching {url}.", slug)
    try:
        with opener.open(request, timeout=timeout) as response:  # nosec - fixed provider URLs or seeded CTI targets
            status = int(getattr(response, "status", 200) or 200)
            final_url = str(getattr(response, "geturl", lambda: url)() or url)
            header_map = {str(k).lower(): str(v) for k, v in response.headers.items()}
            if max_bytes is not None and max_bytes > 0:
                content = response.read(max_bytes + 1)
                if len(content) > max_bytes:
                    content = content[:max_bytes]
            else:
                content = response.read()
            return status, content.decode("utf-8", errors="replace"), final_url, header_map
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        header_map = {str(k).lower(): str(v) for k, v in exc.headers.items()}
        return int(exc.code or 0), body, url, header_map
    except Exception as exc:
        ctx.warning(f"{slug} request failed: {exc}", slug)
        return 0, "", url, {}


def _resolve_host_addresses(host: str) -> list[str]:
    candidate = _normalize_indicator(host)
    if not candidate or _valid_ip(candidate):
        return [candidate] if candidate else []
    addresses: set[str] = set()
    try:
        for family, _, _, _, sockaddr in socket.getaddrinfo(candidate, None):
            if family == socket.AF_INET:
                addresses.add(str(sockaddr[0]))
            elif family == socket.AF_INET6:
                addresses.add(str(sockaddr[0]))
    except Exception:
        return []
    return sorted(addresses)


def _reverse_resolve(address: str) -> list[str]:
    names: set[str] = set()
    try:
        primary, aliases, _ = socket.gethostbyaddr(address)
    except Exception:
        return []
    for value in [primary, *aliases]:
        candidate = _normalize_indicator(value)
        if candidate:
            names.add(candidate)
    return sorted(names)


def _host_resolves_to_address(host: str, address: str) -> bool:
    candidate = _normalize_indicator(host)
    if not candidate:
        return False
    try:
        addrs = socket.getaddrinfo(candidate, None)
    except Exception:
        return False
    for family, _, _, _, sockaddr in addrs:
        if family == socket.AF_INET and str(sockaddr[0]) == address:
            return True
        if family == socket.AF_INET6 and str(sockaddr[0]) == address:
            return True
    return False


def _root_matches(candidate: str, root_target: str) -> bool:
    cand = _normalize_indicator(candidate)
    root = _normalize_indicator(root_target)
    if not cand or not root:
        return False
    if cand == root:
        return True
    if _valid_ip(cand) or _valid_ip(root):
        return cand == root
    return cand.endswith("." + root) or root.endswith("." + cand)


def _related_bucket_seeds(value: str) -> list[str]:
    host = _normalize_indicator(value)
    if not host or _valid_ip(host):
        return []
    seeds: list[str] = []
    condensed = host.replace(".", "")
    if condensed:
        seeds.append(condensed)
    keyword = _domain_keyword(host)
    if keyword and keyword not in seeds:
        seeds.append(keyword)
    return seeds


def _bucket_urls(seeds: list[str], suffixes: list[str], endpoint: str) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    for seed in seeds:
        for suffix in ["", *suffixes]:
            bucket = f"{seed}{suffix}".lower().strip()
            if not bucket:
                continue
            if bucket in seen:
                continue
            seen.add(bucket)
            urls.append(f"https://{bucket}.{endpoint}")
    return urls


def _bucket_url_value(value: str) -> str:
    parsed = urllib.parse.urlparse(str(value or "").strip())
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
    return str(value or "").strip().rstrip("/")


def _probe_urls_parallel(
    urls: list[str],
    timeout: int,
    ctx,
    slug: str,
    *,
    max_workers: int = 12,
) -> list[tuple[str, int, str, str, dict[str, str]]]:
    unique_urls = list(dict.fromkeys(urls))
    if not unique_urls:
        return []

    results: list[tuple[str, int, str, str, dict[str, str]]] = []
    worker_count = max(1, min(max_workers, len(unique_urls)))
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = {
            executor.submit(_fetch_http, url, timeout, ctx, slug): url
            for url in unique_urls
        }
        for future in as_completed(futures):
            url = futures[future]
            try:
                status, content, final_url, headers = future.result()
            except Exception as exc:
                ctx.warning(f"{slug} probe failed for {url}: {exc}", slug)
                continue
            results.append((url, status, content, final_url, headers))
    return results


def _bucket_host_from_url(value: str, marker: str) -> str:
    parsed = urllib.parse.urlparse(str(value or "").strip())
    host = _normalize_indicator(parsed.hostname or "")
    if host and marker in host:
        return host
    return ""


def _root_host(value: str) -> str:
    parsed = urllib.parse.urlparse(str(value or "").strip())
    host = _normalize_indicator(parsed.hostname or "")
    if host:
        return host
    return _normalize_indicator(value)


def _url_base(value: str) -> str:
    parsed = urllib.parse.urlparse(str(value or "").strip())
    if not parsed.scheme or not parsed.netloc:
        return ""
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def _robots_disallow_rules(content: str) -> list[str]:
    rules: list[str] = []
    for line in str(content or "").splitlines():
        row = str(line or "").strip()
        if not row.lower().startswith("disallow:"):
            continue
        match = re.match(r"disallow:\s*(.[^ #]*)", row, re.IGNORECASE)
        if match:
            rules.append(match.group(1))
    return rules


def _robots_blocks_url(url: str, rules: list[str]) -> bool:
    if not rules:
        return False
    lower_url = str(url or "").strip().lower()
    parsed = urllib.parse.urlparse(lower_url)
    path = (parsed.path or "/").lower()
    for blocked in rules:
        token = str(blocked or "").strip().lower()
        if not token:
            continue
        if token == "*":
            return True
        if path.startswith(token) or token in lower_url:
            return True
    return False


def _s3_bucket_from_url(value: str, endpoints: set[str]) -> str:
    parsed = urllib.parse.urlparse(str(value or "").strip())
    host = _normalize_indicator(parsed.hostname or "")
    if not host or ".amazonaws.com" not in host:
        return ""
    if host in endpoints:
        path_bits = [bit for bit in str(parsed.path or "").split("/") if bit]
        if path_bits:
            return f"{host}/{path_bits[0]}"
    return host


def _dns_encode_name(name: str) -> bytes:
    parts = []
    for label in str(name or "").strip(".").split("."):
        encoded = label.encode("idna", errors="ignore")
        parts.append(bytes([len(encoded)]))
        parts.append(encoded)
    parts.append(b"\x00")
    return b"".join(parts)


def _dns_read_name(packet: bytes, offset: int, visited: set[int] | None = None) -> tuple[str, int]:
    labels: list[str] = []
    visited = set() if visited is None else set(visited)
    start = offset
    jumped = False

    while offset < len(packet):
        length = packet[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("Truncated DNS compression pointer")
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            if pointer in visited:
                raise ValueError("Recursive DNS compression pointer")
            visited.add(pointer)
            pointed_name, _ = _dns_read_name(packet, pointer, visited)
            if pointed_name:
                labels.append(pointed_name)
            offset += 2
            jumped = True
            break
        offset += 1
        if offset + length > len(packet):
            raise ValueError("Truncated DNS label")
        label = packet[offset:offset + length].decode("idna", errors="ignore")
        labels.append(label)
        offset += length

    if not jumped:
        return ".".join(bit for bit in labels if bit).rstrip("."), offset
    return ".".join(bit for bit in labels if bit).rstrip("."), offset


def _dns_parse_rr(packet: bytes, offset: int) -> tuple[dict[str, Any], int]:
    name, offset = _dns_read_name(packet, offset)
    if offset + 10 > len(packet):
        raise ValueError("Truncated DNS resource record")
    rtype, _rclass, ttl, rdlength = struct.unpack("!HHIH", packet[offset:offset + 10])
    offset += 10
    end = offset + rdlength
    if end > len(packet):
        raise ValueError("Truncated DNS rdata")

    text = ""
    if rtype == 1 and rdlength == 4:
        text = socket.inet_ntoa(packet[offset:end])
    elif rtype == 28 and rdlength == 16:
        text = str(ipaddress.IPv6Address(packet[offset:end]))
    elif rtype in {2, 5, 12}:
        text, _ = _dns_read_name(packet, offset)
    elif rtype == 15 and rdlength >= 2:
        preference = struct.unpack("!H", packet[offset:offset + 2])[0]
        exchange, _ = _dns_read_name(packet, offset + 2)
        text = f"{preference} {exchange}".strip()
    elif rtype == 16:
        parts: list[str] = []
        cursor = offset
        while cursor < end:
            length = packet[cursor]
            cursor += 1
            parts.append(packet[cursor:cursor + length].decode("utf-8", errors="replace"))
            cursor += length
        text = " ".join(parts).strip()
    elif rtype == 6:
        mname, cursor = _dns_read_name(packet, offset)
        rname, cursor = _dns_read_name(packet, cursor)
        if cursor + 20 <= end:
            serial, refresh, retry, expire, minimum = struct.unpack("!IIIII", packet[cursor:cursor + 20])
            text = f"{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"
        else:
            text = f"{mname} {rname}".strip()
    else:
        text = packet[offset:end].hex()

    return {
        "name": name.rstrip("."),
        "type": _DNS_TYPE_NAMES.get(rtype, str(rtype)),
        "ttl": int(ttl),
        "text": text.strip(),
    }, end


def _dns_parse_message(packet: bytes) -> list[dict[str, Any]]:
    if len(packet) < 12:
        return []
    _tid, _flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", packet[:12])
    offset = 12

    try:
        for _ in range(qdcount):
            _, offset = _dns_read_name(packet, offset)
            offset += 4
    except Exception:
        return []

    records: list[dict[str, Any]] = []
    total = ancount + nscount + arcount
    for _ in range(total):
        try:
            record, offset = _dns_parse_rr(packet, offset)
        except Exception:
            break
        records.append(record)
    return records


def _dns_query_udp(server: str, name: str, qtype: int, timeout: int = 5) -> bytes | None:
    question = _dns_encode_name(name) + struct.pack("!HH", qtype, 1)
    packet_id = random.randint(0, 65535)
    packet = struct.pack("!HHHHHH", packet_id, 0x0100, 1, 0, 0, 0) + question

    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, (server, 53))
            response, _ = sock.recvfrom(8192)
    except Exception:
        return None

    if len(response) < 2:
        return None
    response_id = struct.unpack("!H", response[:2])[0]
    if response_id != packet_id:
        return None
    return response


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    received = 0
    while received < size:
        chunk = sock.recv(size - received)
        if not chunk:
            break
        chunks.append(chunk)
        received += len(chunk)
    return b"".join(chunks)


def _dns_axfr_records(server: str, zone_name: str, timeout: int) -> list[dict[str, Any]]:
    packet_id = random.randint(0, 65535)
    question = _dns_encode_name(zone_name) + struct.pack("!HH", 252, 1)
    packet = struct.pack("!HHHHHH", packet_id, 0x0100, 1, 0, 0, 0) + question

    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    records: list[dict[str, Any]] = []
    soa_seen = 0

    try:
        with socket.create_connection((server, 53), timeout=timeout) as sock:
            sock.sendall(struct.pack("!H", len(packet)) + packet)
            sock.settimeout(timeout)

            while True:
                length_prefix = _recv_exact(sock, 2)
                if len(length_prefix) != 2:
                    break
                message_length = struct.unpack("!H", length_prefix)[0]
                if message_length <= 0:
                    break
                message = _recv_exact(sock, message_length)
                if len(message) != message_length:
                    break
                parsed = _dns_parse_message(message)
                if not parsed:
                    break
                records.extend(parsed)
                soa_seen += sum(1 for record in parsed if record.get("type") == "SOA")
                if soa_seen >= 2:
                    break
    except Exception:
        return []

    return records


def _rr_to_text(record: dict[str, Any]) -> str:
    name = str(record.get("name", "") or "").strip(".")
    ttl = int(record.get("ttl", 0) or 0)
    rtype = str(record.get("type", "") or "").strip().upper()
    text = str(record.get("text", "") or "").strip()
    if text:
        return f"{name} {ttl} IN {rtype} {text}".strip()
    return f"{name} {ttl} IN {rtype}".strip()


def _nslookup_nameservers(domain: str) -> list[str]:
    try:
        completed = subprocess.run(
            ["nslookup", "-type=ns", domain],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except Exception:
        return []

    output = "\n".join([completed.stdout or "", completed.stderr or ""])
    nameservers: list[str] = []
    seen: set[str] = set()
    for pattern in (
        re.compile(r"nameserver\s*=\s*(\S+)", re.I),
        re.compile(r"nameservers\s*=\s*(\S+)", re.I),
    ):
        for match in pattern.findall(output):
            candidate = str(match or "").strip().rstrip(".")
            if candidate and candidate not in seen:
                seen.add(candidate)
                nameservers.append(candidate)
    return nameservers


class AzureBlobFinderModule(BaseModule):
    slug = "azure-blob-finder"
    name = "Azure Blob Finder"
    watched_types = {"domain", "linked_url_external"}
    produced_types = {"cloud_storage_bucket"}
    requires_key = False

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        if event.event_type == "linked_url_external":
            bucket = _bucket_host_from_url(event.value, ".blob.core.windows.net")
            if bucket:
                yield self._bucket_event(bucket, event, ctx)
            return

        timeout = _http_timeout(ctx, 10)
        max_workers = _probe_thread_count(ctx, self.slug, 20)
        suffixes = _split_csv(
            _module_setting(ctx, self.slug, self.slug, "suffixes", ",".join(DEFAULT_BUCKET_SUFFIXES)),
            DEFAULT_BUCKET_SUFFIXES,
        )
        urls = _bucket_urls(_related_bucket_seeds(event.value), suffixes, "blob.core.windows.net")
        for child in self._events_from_probe_results(
            _probe_urls_parallel(urls, timeout, ctx, self.slug, max_workers=max_workers),
            event,
            ctx,
        ):
            yield child

    def _bucket_event(self, bucket: str, parent_event: ScanEvent, ctx) -> ScanEvent:
        return _make_event(
            event_type="cloud_storage_bucket",
            value=bucket,
            slug=self.slug,
            parent_event=parent_event,
            ctx=ctx,
            risk_score=20,
            confidence=75,
            tags=[self.slug, "cloud", "azure", "bucket"],
            raw_payload={"bucket": bucket, "spiderfoot_parity": True},
        )

    def _events_from_probe_results(
        self,
        results: list[tuple[str, int, str, str, dict[str, str]]],
        parent_event: ScanEvent,
        ctx,
    ) -> list[ScanEvent]:
        events: list[ScanEvent] = []
        seen: set[str] = set()
        for original_url, status, _content, final_url, _headers in results:
            if status <= 0:
                continue
            bucket_value = str(final_url or original_url or "").strip().rstrip("/")
            bucket_host = _normalize_indicator(bucket_value)
            if not bucket_value or not bucket_host or bucket_host in seen:
                continue
            seen.add(bucket_host)
            events.append(self._bucket_event(bucket_value, parent_event, ctx))
        return events


class DoSpaceFinderModule(BaseModule):
    slug = "do-space-finder"
    name = "Digital Ocean Space Finder"
    watched_types = {"domain", "linked_url_external"}
    produced_types = {"cloud_storage_bucket", "cloud_storage_bucket_open"}
    requires_key = False

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        if event.event_type == "linked_url_external":
            bucket = _bucket_host_from_url(event.value, ".digitaloceanspaces.com")
            if bucket:
                for child in self._bucket_events(bucket, 0, event, ctx, emit_open=False):
                    yield child
            return

        timeout = _http_timeout(ctx, 10)
        max_workers = _probe_thread_count(ctx, self.slug, 20)
        endpoints = _split_csv(
            _module_setting(ctx, self.slug, self.slug, ("locations", "endpoints"), ",".join(DEFAULT_DO_ENDPOINTS)),
            DEFAULT_DO_ENDPOINTS,
        )
        suffixes = _split_csv(
            _module_setting(ctx, self.slug, self.slug, "suffixes", ",".join(DEFAULT_BUCKET_SUFFIXES)),
            DEFAULT_BUCKET_SUFFIXES,
        )
        urls: list[str] = []
        for endpoint in endpoints:
            urls.extend(_bucket_urls(_related_bucket_seeds(event.value), suffixes, endpoint))

        for child in self._events_from_probe_results(
            _probe_urls_parallel(urls, timeout, ctx, self.slug, max_workers=max_workers),
            event,
            ctx,
        ):
            yield child

    def _bucket_events(
        self,
        bucket_value: str,
        file_count: int,
        parent_event: ScanEvent,
        ctx,
        *,
        emit_open: bool,
        bucket_host: str | None = None,
    ) -> list[ScanEvent]:
        host = _normalize_indicator(bucket_host or bucket_value)
        value = str(bucket_value or "").strip()
        events = [
            _make_event(
                event_type="cloud_storage_bucket",
                value=value,
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=25,
                confidence=75,
                tags=[self.slug, "cloud", "digitalocean", "bucket"],
                raw_payload={
                    "bucket": host or value,
                    "bucket_value": value,
                    "file_count": file_count,
                    "spiderfoot_parity": True,
                },
            )
        ]
        if emit_open and file_count > 0:
            events.append(_make_event(
                event_type="cloud_storage_bucket_open",
                value=f"{value}: {file_count} files found.",
                slug=self.slug,
                parent_event=events[0],
                ctx=ctx,
                risk_score=55,
                confidence=80,
                tags=[self.slug, "cloud", "digitalocean", "public-bucket"],
                raw_payload={
                    "bucket": host or value,
                    "bucket_value": value,
                    "file_count": file_count,
                    "spiderfoot_parity": True,
                },
            ))
        return events

    def _events_from_probe_results(
        self,
        results: list[tuple[str, int, str, str, dict[str, str]]],
        parent_event: ScanEvent,
        ctx,
    ) -> list[ScanEvent]:
        events: list[ScanEvent] = []
        seen: set[str] = set()
        for original_url, status, content, final_url, _headers in results:
            if status not in {200, 301, 302}:
                continue
            if not content or "NoSuchBucket" in content or "ListBucketResult" not in content:
                continue
            file_count = content.count("<Key>")
            if file_count <= 0:
                continue
            bucket_value = _bucket_url_value(final_url or original_url)
            bucket_host = _normalize_indicator(bucket_value)
            if not bucket_value or not bucket_host or bucket_host in seen:
                continue
            seen.add(bucket_host)
            events.extend(self._bucket_events(
                bucket_value,
                file_count,
                parent_event,
                ctx,
                emit_open=True,
                bucket_host=bucket_host,
            ))
        return events


class GcsFinderModule(BaseModule):
    slug = "gcs-finder"
    name = "Google Object Storage Finder"
    watched_types = {"domain", "linked_url_external"}
    produced_types = {"cloud_storage_bucket", "cloud_storage_bucket_open"}
    requires_key = False

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        if event.event_type == "linked_url_external":
            bucket = _bucket_host_from_url(event.value, ".storage.googleapis.com")
            if bucket:
                for child in self._bucket_events(bucket, 0, event, ctx, emit_open=False):
                    yield child
            return

        timeout = _http_timeout(ctx, 10)
        max_workers = _probe_thread_count(ctx, self.slug, 20)
        suffixes = _split_csv(
            _module_setting(ctx, self.slug, self.slug, "suffixes", ",".join(DEFAULT_BUCKET_SUFFIXES)),
            DEFAULT_BUCKET_SUFFIXES,
        )
        urls = _bucket_urls(_related_bucket_seeds(event.value), suffixes, "storage.googleapis.com")
        for child in self._events_from_probe_results(
            _probe_urls_parallel(urls, timeout, ctx, self.slug, max_workers=max_workers),
            event,
            ctx,
        ):
            yield child

    def _bucket_events(
        self,
        bucket_value: str,
        file_count: int,
        parent_event: ScanEvent,
        ctx,
        *,
        emit_open: bool,
        bucket_host: str | None = None,
    ) -> list[ScanEvent]:
        host = _normalize_indicator(bucket_host or bucket_value)
        value = str(bucket_value or "").strip()
        events = [
            _make_event(
                event_type="cloud_storage_bucket",
                value=value,
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=25,
                confidence=75,
                tags=[self.slug, "cloud", "gcs", "bucket"],
                raw_payload={
                    "bucket": host or value,
                    "bucket_value": value,
                    "file_count": file_count,
                    "spiderfoot_parity": True,
                },
            )
        ]
        if emit_open and file_count > 0:
            events.append(_make_event(
                event_type="cloud_storage_bucket_open",
                value=f"{host or value}: {file_count} files found.",
                slug=self.slug,
                parent_event=events[0],
                ctx=ctx,
                risk_score=55,
                confidence=80,
                tags=[self.slug, "cloud", "gcs", "public-bucket"],
                raw_payload={
                    "bucket": host or value,
                    "bucket_value": value,
                    "file_count": file_count,
                    "spiderfoot_parity": True,
                },
            ))
        return events

    def _events_from_probe_results(
        self,
        results: list[tuple[str, int, str, str, dict[str, str]]],
        parent_event: ScanEvent,
        ctx,
    ) -> list[ScanEvent]:
        events: list[ScanEvent] = []
        seen: set[str] = set()
        for original_url, status, content, final_url, _headers in results:
            if status not in {200, 301, 302}:
                continue
            if not content or "NoSuchBucket" in content or "ListBucketResult" not in content:
                continue
            file_count = content.count("<Key>")
            if file_count <= 0:
                continue
            bucket_value = _bucket_url_value(final_url or original_url)
            bucket_host = _normalize_indicator(bucket_value)
            if not bucket_value or not bucket_host or bucket_host in seen:
                continue
            seen.add(bucket_host)
            events.extend(self._bucket_events(
                bucket_value,
                file_count,
                parent_event,
                ctx,
                emit_open=True,
                bucket_host=bucket_host,
            ))
        return events


class S3FinderModule(BaseModule):
    slug = "s3-finder"
    name = "Amazon S3 Bucket Finder"
    watched_types = {"domain", "linked_url_external"}
    produced_types = {"cloud_storage_bucket", "cloud_storage_bucket_open"}
    requires_key = False

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        endpoints = _split_csv(
            _module_setting(ctx, self.slug, self.slug, "endpoints", ",".join(DEFAULT_S3_ENDPOINTS)),
            DEFAULT_S3_ENDPOINTS,
        )
        endpoint_set = set(endpoints)

        if event.event_type == "linked_url_external":
            bucket = _s3_bucket_from_url(event.value, endpoint_set)
            if bucket:
                yield self._bucket_event(bucket, 0, event, ctx)
            return

        timeout = _http_timeout(ctx, 10)
        max_workers = _probe_thread_count(ctx, self.slug, 20)
        suffixes = _split_csv(
            _module_setting(ctx, self.slug, self.slug, "suffixes", ",".join(DEFAULT_BUCKET_SUFFIXES)),
            DEFAULT_BUCKET_SUFFIXES,
        )
        urls: list[str] = []
        for endpoint in endpoints:
            urls.extend(_bucket_urls(_related_bucket_seeds(event.value), suffixes, endpoint))
        for child in self._events_from_probe_results(
            _probe_urls_parallel(urls, timeout, ctx, self.slug, max_workers=max_workers),
            event,
            ctx,
        ):
            yield child

    def _bucket_event(
        self,
        bucket_value: str,
        file_count: int,
        parent_event: ScanEvent,
        ctx,
        *,
        bucket_host: str | None = None,
    ) -> ScanEvent:
        host = _normalize_indicator(bucket_host or bucket_value)
        return _make_event(
            event_type="cloud_storage_bucket",
            value=bucket_value,
            slug=self.slug,
            parent_event=parent_event,
            ctx=ctx,
            risk_score=25,
            confidence=75,
            tags=[self.slug, "cloud", "s3", "bucket"],
            raw_payload={
                "bucket": host or bucket_value,
                "bucket_value": bucket_value,
                "file_count": file_count,
                "spiderfoot_parity": True,
            },
        )

    def _events_from_probe_results(
        self,
        results: list[tuple[str, int, str, str, dict[str, str]]],
        parent_event: ScanEvent,
        ctx,
    ) -> list[ScanEvent]:
        events: list[ScanEvent] = []
        seen: set[str] = set()
        for original_url, status, content, final_url, _headers in results:
            if status not in {200, 301, 302}:
                continue
            if not content or "NoSuchBucket" in content or "ListBucketResult" not in content:
                continue
            file_count = content.count("<Key>")
            if file_count <= 0:
                continue
            bucket_value = str(final_url or original_url or "").strip().rstrip("/")
            bucket_host = _normalize_indicator(bucket_value)
            if not bucket_value or not bucket_host or bucket_host in seen:
                continue
            seen.add(bucket_host)
            bucket_event = self._bucket_event(bucket_value, file_count, parent_event, ctx, bucket_host=bucket_host)
            events.append(bucket_event)
            events.append(_make_event(
                event_type="cloud_storage_bucket_open",
                value=f"{bucket_host}: {file_count} files found.",
                slug=self.slug,
                parent_event=bucket_event,
                ctx=ctx,
                risk_score=55,
                confidence=80,
                tags=[self.slug, "cloud", "s3", "public-bucket"],
                raw_payload={"bucket": bucket_host, "bucket_value": bucket_value, "file_count": file_count, "spiderfoot_parity": True},
            ))
        return events


class DnsLookasideModule(BaseModule):
    slug = "dns-lookaside"
    name = "DNS Look-aside"
    watched_types = {"domain", "ip", "ipv6", "internet_name"}
    produced_types = {"ip", "ipv6", "affiliate_ipaddr", "affiliate_ipv6"}
    requires_key = False

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        lookaside_bits = max(1, _module_int(
            ctx,
            self.slug,
            self.slug,
            ("netmask_size", "lookasidebits"),
            4,
        ))
        validate_reverse = _module_bool(
            ctx,
            self.slug,
            self.slug,
            ("validate_reverse", "validatereverse"),
            True,
        )

        seed_addresses: list[str] = []
        if event.event_type in {"ip", "ipv6"} and _valid_ip(event.value):
            seed_addresses = [event.value.strip()]
        else:
            seed_addresses = _resolve_host_addresses(event.value)

        seen: set[tuple[str, str]] = set()
        for address in seed_addresses:
            for child in self._events_from_seed_ip(
                address,
                event,
                ctx,
                lookaside_bits=lookaside_bits,
                validate_reverse=validate_reverse,
            ):
                pair = (child.event_type, child.value)
                if pair in seen:
                    continue
                seen.add(pair)
                yield child

    def _events_from_seed_ip(
        self,
        address: str,
        parent_event: ScanEvent,
        ctx,
        *,
        lookaside_bits: int,
        validate_reverse: bool,
    ) -> list[ScanEvent]:
        if not _valid_ip(address):
            return []
        try:
            ip_obj = ipaddress.ip_address(address)
        except ValueError:
            return []

        prefix = ip_obj.max_prefixlen - min(ip_obj.max_prefixlen, lookaside_bits)
        network = ipaddress.ip_network(f"{address}/{prefix}", strict=False)
        reverse_map: dict[str, list[str]] = {}
        for neighbour in network:
            neighbour_value = str(neighbour)
            if neighbour_value == address:
                continue
            names = _reverse_resolve(neighbour_value)
            if not names:
                continue
            if validate_reverse:
                names = [name for name in names if _host_resolves_to_address(name, neighbour_value)]
            if names:
                reverse_map[neighbour_value] = names
        return self._events_from_reverse_map(reverse_map, parent_event, ctx)

    def _events_from_reverse_map(
        self,
        reverse_map: dict[str, list[str]],
        parent_event: ScanEvent,
        ctx,
    ) -> list[ScanEvent]:
        events: list[ScanEvent] = []
        seen: set[str] = set()
        root = ctx.root_target
        for address, names in reverse_map.items():
            if address in seen:
                continue
            seen.add(address)
            affiliate = not (
                _root_matches(address, root)
                or any(_root_matches(name, root) for name in names)
            )
            if ":" in address:
                event_type = "affiliate_ipv6" if affiliate else "ipv6"
            else:
                event_type = "affiliate_ipaddr" if affiliate else "ip"
            events.append(_make_event(
                event_type=event_type,
                value=address,
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=5 if affiliate else 0,
                confidence=70,
                tags=[self.slug, "dns", "lookaside"],
                raw_payload={"reverse_names": names, "spiderfoot_parity": True},
            ))
        return events


class DnsZoneTransferModule(BaseModule):
    slug = "dns-zone-transfer"
    name = "DNS Zone Transfer"
    watched_types = {"domain", "provider_dns"}
    produced_types = {"raw_dns_records", "internet_name"}
    requires_key = False

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        timeout = max(1, _module_int(ctx, self.slug, self.slug, "timeout", 30))
        zone_name = _normalize_indicator(ctx.root_target if event.event_type == "provider_dns" else event.value)
        if not zone_name or _valid_ip(zone_name):
            return

        if event.event_type == "provider_dns":
            nameservers = [_normalize_indicator(event.value)] if _normalize_indicator(event.value) else []
        else:
            nameservers = _nslookup_nameservers(zone_name)

        seen: set[tuple[str, str]] = set()
        for nameserver in nameservers:
            for ns_ip in _resolve_host_addresses(nameserver) or [nameserver]:
                records = _dns_axfr_records(ns_ip, zone_name, timeout)
                if not records:
                    continue
                for child in self._events_from_transfer_records(records, event, ctx):
                    pair = (child.event_type, child.value)
                    if pair in seen:
                        continue
                    seen.add(pair)
                    yield child

    def _events_from_transfer_records(
        self,
        records: list[dict[str, Any]],
        parent_event: ScanEvent,
        ctx,
    ) -> list[ScanEvent]:
        if not records:
            return []

        raw_rows = [_rr_to_text(record) for record in records if record.get("name")]
        if not raw_rows:
            return []

        events: list[ScanEvent] = [
            _make_event(
                event_type="raw_dns_records",
                value="\n".join(raw_rows),
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=75,
                confidence=85,
                tags=[self.slug, "dns", "zone-transfer"],
                raw_payload={"record_count": len(raw_rows), "spiderfoot_parity": True},
            )
        ]

        seen_hosts: set[str] = set()
        zone_name = _normalize_indicator(ctx.root_target if not _valid_ip(ctx.root_target) else parent_event.value)
        pattern = re.compile(r"^(\S+)\.?\s+\d+\s+IN\s+[AC].*", re.I)
        for row in raw_rows:
            matches = pattern.findall(row)
            for host in matches:
                candidate = str(host or "").strip().rstrip(".")
                if not candidate:
                    continue
                if "." not in candidate and zone_name:
                    candidate = f"{candidate}.{zone_name}"
                candidate = candidate.rstrip(".")
                if candidate in seen_hosts:
                    continue
                seen_hosts.add(candidate)
                events.append(_make_event(
                    event_type="internet_name",
                    value=candidate,
                    slug=self.slug,
                    parent_event=parent_event,
                    ctx=ctx,
                    risk_score=25,
                    confidence=75,
                    tags=[self.slug, "dns", "zone-transfer"],
                    raw_payload={"row": row, "spiderfoot_parity": True},
                ))
        return events


class DnsTwistModule(BaseModule):
    slug = "dnstwist"
    name = "Tool - DNSTwist"
    watched_types = {"domain"}
    produced_types = {"similardomain"}
    requires_key = False

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        domain = _normalize_indicator(event.value)
        if not domain or _valid_ip(domain):
            return

        domain_keyword = _domain_keyword(domain)
        if _module_bool(ctx, self.slug, self.slug, ("skip_wildcards", "skipwildcards"), True):
            if domain_keyword and f"{domain_keyword}." in domain:
                tld = domain.split(domain_keyword + ".", 1)[-1]
            else:
                tld = domain.rsplit(".", 1)[-1]
            if self._has_wildcard_tld(tld):
                ctx.debug(f"Wildcard DNS detected on {domain} TLD: {tld}", self.slug)
                return

        variants = self._tool_variants(ctx, domain)
        if variants is None:
            variants = self._fallback_variants(domain)

        for child in self._events_from_variants(variants, event, ctx):
            yield child

    def _tool_variants(self, ctx, domain: str) -> list[str] | None:
        tool_path = str(_module_setting(ctx, self.slug, self.slug, ("dnstwist_path", "tool_path", "dnstwistpath"), "") or "").strip()
        python_path = str(_module_setting(ctx, self.slug, self.slug, ("python_path", "pythonpath"), "python") or "python").strip()

        if tool_path:
            path = Path(tool_path)
            if path.is_dir():
                executable = path / "dnstwist.py"
            else:
                executable = path
            if executable.is_file():
                if executable.suffix.lower() == ".py":
                    cmd = [python_path, str(executable)]
                else:
                    cmd = [str(executable)]
            else:
                ctx.warning(f"DNSTwist path is invalid: {tool_path}", self.slug)
                return []
        else:
            auto = which("dnstwist")
            cmd = [auto] if auto else []

        if not cmd:
            return None

        try:
            completed = subprocess.run(
                [*cmd, "-f", "json", "-r", domain],
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )
        except Exception as exc:
            ctx.warning(f"DNSTwist execution failed: {exc}", self.slug)
            return []

        if completed.returncode != 0:
            stderr = str(completed.stderr or "").strip()
            if stderr:
                ctx.warning(f"DNSTwist returned an error: {stderr}", self.slug)
            return []

        try:
            payload = json.loads(completed.stdout or "[]")
        except Exception as exc:
            ctx.warning(f"Could not parse DNSTwist JSON output: {exc}", self.slug)
            return []

        variants: list[str] = []
        for row in payload if isinstance(payload, list) else []:
            if not isinstance(row, dict):
                continue
            value = str(row.get("domain-name") or row.get("domain") or "").strip().lower()
            if value:
                variants.append(value)
        return variants

    def _fallback_variants(self, domain: str) -> list[str]:
        keyword, _, tld = domain.partition(".")
        if not keyword or not tld:
            return []
        variants: set[str] = set()

        for index in range(len(keyword)):
            deletion = keyword[:index] + keyword[index + 1:]
            if deletion:
                variants.add(f"{deletion}.{tld}")

        for index in range(len(keyword) - 1):
            chars = list(keyword)
            chars[index], chars[index + 1] = chars[index + 1], chars[index]
            variants.add(f"{''.join(chars)}.{tld}")

        for index in range(1, len(keyword)):
            variants.add(f"{keyword[:index]}-{keyword[index:]}.{tld}")

        for index in range(len(keyword)):
            variants.add(f"{keyword}{keyword[index]}.{tld}")

        vowels = "aeiou"
        for index, char in enumerate(keyword):
            if char not in vowels:
                continue
            for replacement in vowels:
                if replacement == char:
                    continue
                variants.add(f"{keyword[:index]}{replacement}{keyword[index + 1:]}.{tld}")

        common_tlds = ["com", "net", "org", "co", "io", "biz", "info", "app"]
        for alt_tld in common_tlds:
            if alt_tld != tld:
                variants.add(f"{keyword}.{alt_tld}")

        registered = [variant for variant in sorted(variants)[:250] if _host_resolves(variant)]
        return registered

    def _has_wildcard_tld(self, tld: str) -> bool:
        random_host = f"cti-{random.randint(100000, 999999)}.{tld}"
        return _host_resolves(random_host)

    def _events_from_variants(
        self,
        variants: list[str],
        parent_event: ScanEvent,
        ctx,
    ) -> list[ScanEvent]:
        root = _normalize_indicator(parent_event.value)
        events: list[ScanEvent] = []
        seen: set[str] = set()
        for variant in variants:
            candidate = _normalize_indicator(variant)
            if not candidate or candidate == root or candidate in seen:
                continue
            if _matches_root_target(candidate, root):
                continue
            seen.add(candidate)
            events.append(_make_event(
                event_type="similardomain",
                value=candidate,
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=20,
                confidence=75,
                tags=[self.slug, "dns", "typosquat"],
                raw_payload={"variant": candidate, "spiderfoot_parity": True},
            ))
        return events


class OpenPdnsModule(BaseModule):
    slug = "open-pdns"
    name = "Open Passive DNS"
    watched_types = {"domain", "ip", "affiliate_ipaddr"}
    produced_types = {
        "raw_rir_data",
        "ip",
        "ipv6",
        "internet_name",
        "affiliate_internet_name",
        "co_hosted_site",
    }
    requires_key = False

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        target = _normalize_indicator(event.value)
        if not target:
            return

        timeout = max(1, _module_int(ctx, self.slug, self.slug, ("timeout_seconds", "timeout"), 30))
        url = "https://www.circl.lu/pdns/query/" + urllib.parse.quote(target, safe="")
        content = _fetch_text(url, timeout, ctx, self.slug, accept="application/json, text/plain, */*")
        if content is None:
            return

        records = self._parse_records(content)
        for child in self._events_from_records(records, event, ctx):
            yield child

    def _parse_records(self, content: str) -> list[dict[str, Any]]:
        raw = str(content or "").strip()
        if not raw:
            return []
        try:
            payload = json.loads(raw)
            if isinstance(payload, list):
                return [row for row in payload if isinstance(row, dict)]
        except Exception:
            pass

        records: list[dict[str, Any]] = []
        for line in raw.splitlines():
            row = str(line or "").strip()
            if not row:
                continue
            try:
                decoded = json.loads(row)
            except Exception:
                continue
            if isinstance(decoded, dict):
                records.append(decoded)
        return records

    def _events_from_records(
        self,
        records: list[dict[str, Any]],
        parent_event: ScanEvent,
        ctx,
    ) -> list[ScanEvent]:
        if not records:
            return []

        events: list[ScanEvent] = [
            _make_event(
                event_type="raw_rir_data",
                value=json.dumps(records[:25], ensure_ascii=False),
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=5,
                confidence=70,
                tags=[self.slug, "passive-dns", "raw"],
                raw_payload={"record_count": len(records), "spiderfoot_parity": True},
            )
        ]

        seen: set[tuple[str, str]] = set()
        root = ctx.root_target
        parent_ip_query = parent_event.event_type in {"ip", "ipv6", "affiliate_ipaddr"}
        verify_hostnames = _module_bool(ctx, self.slug, self.slug, "verify_hostnames", True)
        parent_address = _normalize_indicator(parent_event.value) if parent_ip_query else ""

        for record in records:
            rrname = _normalize_indicator(record.get("rrname", ""))
            rdata = _normalize_indicator(record.get("rdata", ""))
            rrtype = str(record.get("rrtype", "") or "").strip().upper()

            if not parent_ip_query:
                if _valid_ip(rdata):
                    event_type = "ipv6" if ":" in rdata else "ip"
                    pair = (event_type, rdata)
                    if pair in seen:
                        pass
                    else:
                        seen.add(pair)
                        events.append(_make_event(
                            event_type=event_type,
                            value=rdata,
                            slug=self.slug,
                            parent_event=parent_event,
                            ctx=ctx,
                            risk_score=0,
                            confidence=75,
                            tags=[self.slug, "passive-dns", rrtype.lower()],
                            raw_payload={"record": record, "spiderfoot_parity": True},
                        ))

                if rrname and rrname != _normalize_indicator(parent_event.value):
                    host_event_type = "internet_name" if _root_matches(rrname, root) else "affiliate_internet_name"
                    host_pair = (host_event_type, rrname)
                    if host_pair not in seen:
                        seen.add(host_pair)
                        events.append(_make_event(
                            event_type=host_event_type,
                            value=rrname,
                            slug=self.slug,
                            parent_event=parent_event,
                            ctx=ctx,
                            risk_score=5 if host_event_type == "affiliate_internet_name" else 0,
                            confidence=70,
                            tags=[self.slug, "passive-dns", rrtype.lower()],
                            raw_payload={"record": record, "spiderfoot_parity": True},
                        ))
                continue

            candidate = rrname or rdata
            if not candidate or _valid_ip(candidate):
                continue
            if verify_hostnames and _valid_ip(parent_address):
                resolved = _resolve_host_addresses(candidate)
                if parent_address not in resolved:
                    continue
            if _root_matches(candidate, root):
                event_type = "internet_name"
            else:
                event_type = "co_hosted_site"
            pair = (event_type, candidate)
            if pair in seen:
                continue
            seen.add(pair)
            events.append(_make_event(
                event_type=event_type,
                value=candidate,
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=5 if event_type == "co_hosted_site" else 0,
                confidence=75,
                tags=[self.slug, "passive-dns", rrtype.lower()],
                raw_payload={"record": record, "spiderfoot_parity": True},
            ))

        return events


class OpenNicModule(BaseModule):
    slug = "opennic"
    name = "OpenNIC DNS"
    watched_types = {
        "domain",
        "internet_name",
        "internet_name_unresolved",
        "affiliate_internet_name",
        "affiliate_internet_name_unresolved",
    }
    produced_types = {"ip", "ipv6", "affiliate_ipaddr", "affiliate_ipv6"}
    requires_key = False

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        host = _normalize_indicator(event.value)
        if not host or "." not in host or host.rsplit(".", 1)[-1] not in OPENNIC_TLDS:
            return

        affiliate_source = "affiliate" in event.event_type
        if affiliate_source and not _module_bool(ctx, self.slug, self.slug, "checkaffiliates", True):
            return

        addresses = self._query_opennic(host, _http_timeout(ctx, 5))
        for child in self._events_from_addresses(addresses, event, ctx):
            yield child

    def _query_opennic(self, host: str, timeout: int) -> list[str]:
        addresses: set[str] = set()
        for server in OPENNIC_NAMESERVERS:
            payload = _dns_query_udp(server, host, 1, timeout)
            if not payload:
                continue
            for record in _dns_parse_message(payload):
                value = str(record.get("text", "") or "").strip()
                if _valid_ip(value):
                    addresses.add(value)
            if addresses:
                break
        return sorted(addresses)

    def _events_from_addresses(
        self,
        addresses: list[str],
        parent_event: ScanEvent,
        ctx,
    ) -> list[ScanEvent]:
        affiliate_source = "affiliate" in parent_event.event_type
        events: list[ScanEvent] = []
        seen: set[tuple[str, str]] = set()
        for address in addresses:
            if not _valid_ip(address):
                continue
            if ":" in address:
                if affiliate_source and not _root_matches(address, ctx.root_target):
                    event_type = "affiliate_ipv6"
                else:
                    event_type = "ipv6"
            else:
                if affiliate_source and not _root_matches(address, ctx.root_target):
                    event_type = "affiliate_ipaddr"
                else:
                    event_type = "ip"
            pair = (event_type, address)
            if pair in seen:
                continue
            seen.add(pair)
            events.append(_make_event(
                event_type=event_type,
                value=address,
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=0,
                confidence=80,
                tags=[self.slug, "dns", "opennic"],
                raw_payload={"address": address, "spiderfoot_parity": True},
            ))
        return events


class WebSpiderModule(BaseModule):
    slug = "web-spider"
    name = "Web Spider"
    watched_types = {"domain", "url", "internet_name", "linked_url_internal"}
    produced_types = {
        "webserver_httpheaders",
        "http_code",
        "linked_url_internal",
        "linked_url_external",
        "target_web_content",
        "target_web_content_type",
    }
    requires_key = False

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        if event.source_module == self.slug:
            return

        start_urls = self._starting_urls(event, ctx)
        if not start_urls:
            ctx.info(f"No reply from {event.value}, aborting.", self.slug)
            return

        max_pages = max(1, _module_int(ctx, self.slug, self.slug, ("maxpages", "max_pages"), 100))
        max_levels = max(0, _module_int(ctx, self.slug, self.slug, ("maxlevels", "max_levels"), 3))
        pausesec = max(0, _module_int(ctx, self.slug, self.slug, ("pausesec", "pause_seconds"), 0))
        reportduplicates = _module_bool(ctx, self.slug, self.slug, "reportduplicates", False)
        usecookies = _module_bool(ctx, self.slug, self.slug, "usecookies", True)

        cookie_jar = http.cookiejar.CookieJar() if usecookies else None
        timeout = _http_timeout(ctx, 15)
        queued: list[tuple[str, int, ScanEvent]] = []
        emitted_links: set[tuple[str, str]] = set()
        seen_pages: set[str] = set()
        seed_emitted: set[str] = set()

        for url in start_urls:
            if url in seed_emitted:
                continue
            seed_emitted.add(url)
            seed_event = _make_event(
                event_type="linked_url_internal",
                value=url,
                slug=self.slug,
                parent_event=event,
                ctx=ctx,
                risk_score=0,
                confidence=80,
                tags=[self.slug, "crawl", "seed-url"],
                raw_payload={"spiderfoot_parity": True},
            )
            yield seed_event
            queued.append((url, 0, seed_event))

        pages_fetched = 0
        while queued and pages_fetched < max_pages:
            if ctx.is_cancelled():
                return

            url, depth, parent_event = queued.pop(0)
            normalized = self._normalize_url(url)
            if normalized in seen_pages:
                continue
            seen_pages.add(normalized)

            status, content, final_url, headers = _fetch_http(
                url,
                timeout,
                ctx,
                self.slug,
                accept="text/html, application/xhtml+xml, */*",
                cookie_jar=cookie_jar,
                max_bytes=MAX_WEB_CONTENT_CHARS,
            )
            if status <= 0:
                continue

            pages_fetched += 1
            page_events = self._events_from_page(final_url, status, headers, content, parent_event, ctx)
            internal_link_events: dict[str, ScanEvent] = {}
            for child in page_events:
                link_pair = (child.event_type, child.value)
                if child.event_type.startswith("linked_url_") and not reportduplicates and link_pair in emitted_links:
                    continue
                if child.event_type.startswith("linked_url_"):
                    emitted_links.add(link_pair)
                if child.event_type == "linked_url_internal":
                    internal_link_events[self._normalize_url(child.value)] = child
                yield child

            if depth >= max_levels:
                continue

            next_links = self._crawlable_internal_links(final_url, content, ctx)
            for link in next_links:
                normalized_link = self._normalize_url(link)
                if normalized_link in seen_pages:
                    continue
                if any(normalized_link == self._normalize_url(queued_url) for queued_url, _, _ in queued):
                    continue
                queued.append((link, depth + 1, internal_link_events.get(normalized_link, parent_event)))

            if pausesec > 0:
                time.sleep(pausesec)

    def _starting_urls(self, event: ScanEvent, ctx) -> list[str]:
        if event.event_type in {"url", "linked_url_internal"}:
            return [event.value.strip()]

        starts = _module_setting(ctx, self.slug, self.slug, "start", ["http://", "https://"])
        prefixes = _split_csv(starts, ["http://", "https://"])
        host = _normalize_indicator(event.value)
        if not host:
            return []

        results: list[str] = []
        for prefix in prefixes:
            url = f"{prefix}{host}"
            status, content, final_url, _headers = _fetch_http(
                url,
                _http_timeout(ctx, 10),
                ctx,
                self.slug,
                accept="text/html, */*",
                max_bytes=8192,
            )
            if status > 0 and content:
                results.append(final_url)
                break
        return results

    def _crawlable_internal_links(self, base_url: str, content: str, ctx) -> list[str]:
        root_host = _root_host(ctx.root_target) or _normalize_indicator(base_url)
        filter_users = _module_bool(ctx, self.slug, self.slug, "filterusers", True)
        no_subs = _module_bool(ctx, self.slug, self.slug, "nosubs", False)
        robots_only = _module_bool(ctx, self.slug, self.slug, "robotsonly", False)
        filter_files = {
            ext.lower()
            for ext in _split_csv(
                _module_setting(
                    ctx,
                    self.slug,
                    self.slug,
                    "filterfiles",
                    "png,gif,jpg,jpeg,tiff,tif,tar,pdf,ico,flv,mp4,mp3,avi,mpg,gz,mpeg,iso,dat,mov,swf,rar,exe,zip,bin,bz2,xsl,doc,docx,ppt,pptx,xls,xlsx,csv",
                ),
                [],
            )
        }
        robots_rules = self._robots_rules_for(base_url, ctx) if robots_only else []
        links: list[str] = []
        seen: set[str] = set()
        for raw_link in HTML_LINK_RX.findall(str(content or "")):
            resolved = urllib.parse.urljoin(base_url, urllib.parse.unquote(str(raw_link or "").strip()))
            if not resolved or resolved.startswith(("javascript:", "mailto:", "tel:", "data:")):
                continue
            parsed = urllib.parse.urlparse(resolved)
            host = _normalize_indicator(parsed.hostname or "")
            if not host or not _matches_root_target(host, root_host):
                continue
            if no_subs and host != root_host:
                continue
            if filter_users and "/~" in (parsed.path or ""):
                continue
            if robots_only and _robots_blocks_url(resolved, robots_rules):
                continue
            ext = Path(parsed.path or "").suffix.lstrip(".").lower()
            if ext and ext in filter_files:
                continue
            normalized = self._normalize_url(resolved)
            if normalized in seen:
                continue
            seen.add(normalized)
            links.append(resolved)
        return links

    def _events_from_page(
        self,
        page_url: str,
        status: int,
        headers: dict[str, str],
        content: str,
        parent_event: ScanEvent,
        ctx,
    ) -> list[ScanEvent]:
        filtermime = [
            item.lower()
            for item in _split_csv(
                _module_setting(ctx, self.slug, self.slug, "filtermime", ["image/"]),
                ["image/"],
            )
        ]
        events: list[ScanEvent] = [
            _make_event(
                event_type="http_code",
                value=str(status),
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=0,
                confidence=90,
                tags=[self.slug, "crawl", "http"],
                raw_payload={"url": page_url, "spiderfoot_parity": True},
            )
        ]

        if headers:
            events.append(_make_event(
                event_type="webserver_httpheaders",
                value=json.dumps(headers, ensure_ascii=False),
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=0,
                confidence=80,
                tags=[self.slug, "crawl", "headers"],
                raw_payload={"url": page_url, "spiderfoot_parity": True},
            ))

        content_type = str(headers.get("content-type", "") or "").replace(" ", "").lower()
        store_content = True
        if content_type:
            events.append(_make_event(
                event_type="target_web_content_type",
                value=content_type,
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=0,
                confidence=80,
                tags=[self.slug, "crawl", "content-type"],
                raw_payload={"url": page_url, "spiderfoot_parity": True},
            ))
            if any(content_type.startswith(prefix) for prefix in filtermime):
                store_content = False

        if store_content and content:
            events.append(_make_event(
                event_type="target_web_content",
                value=str(content or "")[:MAX_WEB_CONTENT_CHARS],
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=0,
                confidence=70,
                tags=[self.slug, "crawl", "content"],
                raw_payload={"url": page_url, "spiderfoot_parity": True},
            ))

        root_host = _root_host(ctx.root_target) or _normalize_indicator(page_url)
        seen_links: set[tuple[str, str]] = set()
        for raw_link in HTML_LINK_RX.findall(str(content or "")):
            resolved = urllib.parse.urljoin(page_url, urllib.parse.unquote(str(raw_link or "").strip()))
            if not resolved or resolved.startswith(("javascript:", "mailto:", "tel:", "data:")):
                continue
            host = _normalize_indicator(resolved)
            if not host:
                continue
            if _matches_root_target(host, root_host):
                event_type = "linked_url_internal"
            else:
                event_type = "linked_url_external"
            pair = (event_type, resolved)
            if pair in seen_links:
                continue
            seen_links.add(pair)
            events.append(_make_event(
                event_type=event_type,
                value=resolved,
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=0,
                confidence=75,
                tags=[self.slug, "crawl", "link"],
                raw_payload={"url": page_url, "spiderfoot_parity": True},
            ))

        return events

    def _normalize_url(self, url: str) -> str:
        parsed = urllib.parse.urlparse(str(url or "").strip())
        if not parsed.scheme:
            return str(url or "").strip().lower().rstrip("/")
        clean = urllib.parse.urlunparse((
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path.rstrip("/"),
            "",
            parsed.query,
            "",
        ))
        return clean.rstrip("/")

    def _robots_rules_for(self, url: str, ctx) -> list[str]:
        base = _url_base(url)
        if not base:
            return []
        cache = getattr(self, "_robots_rules", None)
        if cache is None:
            cache = {}
            setattr(self, "_robots_rules", cache)
        if base in cache:
            return cache[base]

        status, content, _final_url, _headers = _fetch_http(
            base + "/robots.txt",
            _http_timeout(ctx, 15),
            ctx,
            self.slug,
            accept="text/plain, */*",
            max_bytes=65536,
        )
        cache[base] = _robots_disallow_rules(content) if status > 0 and content else []
        return cache[base]


__all__ = [
    "AzureBlobFinderModule",
    "DnsLookasideModule",
    "DnsZoneTransferModule",
    "DnsTwistModule",
    "DoSpaceFinderModule",
    "GcsFinderModule",
    "OpenNicModule",
    "OpenPdnsModule",
    "S3FinderModule",
    "WebSpiderModule",
]
