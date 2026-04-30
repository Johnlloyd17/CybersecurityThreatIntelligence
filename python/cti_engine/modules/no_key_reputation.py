"""No-key SpiderFoot parity modules for the first-party CTI engine."""

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
from typing import Any, AsyncIterator, Iterable

try:  # pragma: no cover - optional dependency for closer AdBlock parity.
    import adblockparser  # type: ignore
except Exception:  # pragma: no cover - intentionally optional.
    adblockparser = None

from ..events import ScanEvent
from ..module_base import BaseModule


USER_AGENT = "CTI Engine"
SERVICE_TO_CTI_SLUG = {
    "adblock": "adblock-check",
    "base64": "base64-decoder",
    "blocklistde": "blocklist-de",
    "cinsscore": "cins-army",
    "cybercrimetracker": "cybercrime-tracker",
    "spamhaus": "spamhaus-zen",
    "stevenblackhosts": "steven-black-hosts",
    "torexits": "tor-exit-nodes",
    "zoneh": "zone-h",
}


def _http_timeout(ctx, default: int = 15) -> int:
    try:
        return int(ctx.request.settings.global_settings.get("http_timeout", default) or default)
    except Exception:
        return default


def _module_setting(ctx, service_slug: str, cti_slug: str, key: Any, default: Any) -> Any:
    settings = {}
    try:
        settings.update(ctx.module_settings_for(service_slug))
        settings.update(ctx.module_settings_for(cti_slug))
    except Exception:
        pass
    keys = list(key) if isinstance(key, (list, tuple, set)) else [key]
    for candidate in keys:
        if candidate in settings:
            return settings.get(candidate, default)
    return default


def _module_bool(ctx, service_slug: str, cti_slug: str, key: Any, default: bool) -> bool:
    value = _module_setting(ctx, service_slug, cti_slug, key, default)
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().lower() not in {"", "0", "false", "no", "off"}


def _module_int(ctx, service_slug: str, cti_slug: str, key: Any, default: int) -> int:
    value = _module_setting(ctx, service_slug, cti_slug, key, default)
    try:
        return int(value)
    except Exception:
        return default


def _cti_slug(service_slug: str) -> str:
    return SERVICE_TO_CTI_SLUG.get(str(service_slug or "").strip().lower(), str(service_slug or "").strip().lower())


def _host_resolves(value: str) -> bool:
    host = str(value or "").strip()
    if not host:
        return False
    try:
        return bool(socket.getaddrinfo(host, None))
    except Exception:
        return False


def _matches_root_target(host: str, root_target: str) -> bool:
    candidate = str(host or "").strip().lower().rstrip(".")
    root = str(root_target or "").strip().lower().rstrip(".")
    if not candidate or not root:
        return False
    if candidate == root:
        return True
    return candidate.endswith("." + root)


def _expand_network_addresses(
    event: ScanEvent,
    ctx,
    service_slug: str,
    cti_slug: str,
    *,
    enabled_keys: Any,
    max_keys: Any,
    enabled_default: bool,
    max_default: int,
    ipv4_only: bool = False,
) -> list[str]:
    network = _parse_network(event.value)
    if network is None:
        return []
    if ipv4_only and network.version != 4:
        return []
    if not _module_bool(ctx, service_slug, cti_slug, enabled_keys, enabled_default):
        return []
    max_size = _module_int(ctx, service_slug, cti_slug, max_keys, max_default)
    if network.prefixlen < max_size:
        ctx.debug(
            f"Network size bigger than permitted: {network.prefixlen} > {max_size}",
            service_slug,
        )
        return []
    return [str(address) for address in network]


def _dnsbl_query_targets(
    event: ScanEvent,
    ctx,
    service_slug: str,
    *,
    affiliate_keys: Any | None = None,
    affiliate_default: bool = True,
    netblock_default: bool = True,
    subnet_default: bool = True,
    ipv4_only: bool = True,
) -> list[str]:
    cti_slug = _cti_slug(service_slug)
    if event.event_type in {"affiliate_ipaddr", "affiliate_ipv6"} and affiliate_keys is not None:
        if not _module_bool(ctx, service_slug, cti_slug, affiliate_keys, affiliate_default):
            return []
    if event.event_type == "netblock_ownership":
        return _expand_network_addresses(
            event,
            ctx,
            service_slug,
            cti_slug,
            enabled_keys=("netblocklookup", "lookup_netblock_ips", "check_netblocks"),
            max_keys=("maxnetblock", "max_netblock_size", "max_netblock_size_ipv4"),
            enabled_default=netblock_default,
            max_default=24,
            ipv4_only=ipv4_only,
        )
    if event.event_type == "netblock_member":
        return _expand_network_addresses(
            event,
            ctx,
            service_slug,
            cti_slug,
            enabled_keys=("subnetlookup", "lookup_subnet_ips", "check_subnets"),
            max_keys=("maxsubnet", "max_subnet_size", "max_subnet_size_ipv4"),
            enabled_default=subnet_default,
            max_default=24,
            ipv4_only=ipv4_only,
        )

    value = event.value.strip()
    if not value:
        return []
    if ipv4_only and not _valid_ipv4(value):
        return []
    return [value]


def _fetch_text(url: str, timeout: int, ctx, slug: str, accept: str = "text/plain, */*") -> str | None:
    request = urllib.request.Request(
        url,
        headers={"Accept": accept, "User-Agent": USER_AGENT},
        method="GET",
    )
    ctx.info(f"Fetching {url}.", slug)

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec - fixed provider URLs
            status = int(getattr(response, "status", 200) or 200)
            content = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        ctx.warning(f"{slug} request failed: HTTP {exc.code}", slug)
        return None
    except Exception as exc:
        ctx.warning(f"{slug} request failed: {exc}", slug)
        return None

    if status != 200:
        ctx.warning(f"{slug} returned HTTP {status}.", slug)
        return None

    return content


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _valid_ipv4(value: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
    except ValueError:
        return False


def _parse_network(value: str) -> ipaddress._BaseNetwork | None:
    try:
        return ipaddress.ip_network(str(value or "").strip(), strict=False)
    except ValueError:
        return None


def _reverse_ipv4(value: str) -> str | None:
    if not _valid_ipv4(value):
        return None
    return ".".join(reversed(value.split(".")))


def _hostname(value: str) -> str:
    candidate = str(value or "").strip().lower()
    if not candidate:
        return ""
    if "://" in candidate:
        try:
            parsed = urllib.parse.urlparse(candidate)
            return str(parsed.hostname or "").strip().lower()
        except Exception:
            return ""
    candidate = candidate.split("/")[0].strip()
    if candidate.startswith("[") and "]" in candidate:
        return candidate[1:candidate.index("]")]
    if ":" in candidate and candidate.count(":") == 1:
        candidate = candidate.split(":", 1)[0]
    return candidate.strip(".").lower()


def _target_indicator(event: ScanEvent) -> str:
    if event.event_type == "url":
        return _hostname(event.value)
    return event.value.strip().lower()


def _event_pair_for(event_type: str) -> tuple[str, str]:
    mapping = {
        "domain": ("malicious_internet_name", "blacklisted_internet_name"),
        "internet_name": ("malicious_internet_name", "blacklisted_internet_name"),
        "domain_name": ("malicious_internet_name", "blacklisted_internet_name"),
        "affiliate_internet_name": ("malicious_affiliate_internet_name", "blacklisted_affiliate_internet_name"),
        "affiliate_domain_name": ("malicious_affiliate_internet_name", "blacklisted_affiliate_internet_name"),
        "co_hosted_site": ("malicious_cohost", "blacklisted_cohost"),
        "co_hosted_site_domain": ("malicious_cohost", "blacklisted_cohost"),
        "ip": ("malicious_ip", "blacklisted_ip"),
        "ipv6": ("malicious_ip", "blacklisted_ip"),
        "affiliate_ipaddr": ("malicious_affiliate_ipaddr", "blacklisted_affiliate_ipaddr"),
        "netblock_ownership": ("malicious_netblock", "blacklisted_netblock"),
        "netblock_member": ("malicious_subnet", "blacklisted_subnet"),
        "hash": ("malicious_hash", "blacklisted_hash"),
        "url": ("malicious_url", "blacklisted_url"),
    }
    return mapping.get(event_type, ("malicious_indicator", "blacklisted_indicator"))


def _make_event(
    *,
    event_type: str,
    value: str,
    slug: str,
    parent_event: ScanEvent,
    ctx,
    risk_score: int,
    confidence: int,
    tags: list[str],
    raw_payload: dict[str, Any],
) -> ScanEvent:
    return ScanEvent(
        event_type=event_type,
        value=value,
        source_module=slug,
        root_target=ctx.root_target,
        parent_event_id=parent_event.event_id,
        confidence=confidence,
        visibility=100,
        risk_score=risk_score,
        tags=tags,
        raw_payload=raw_payload,
    )


def _emit_malicious_and_blacklisted(
    *,
    parent_event: ScanEvent,
    ctx,
    slug: str,
    value: str,
    source_url: str,
    tags: list[str],
    risk_score: int = 85,
    confidence: int = 85,
) -> list[ScanEvent]:
    malicious_type, blacklisted_type = _event_pair_for(parent_event.event_type)
    raw_payload = {
        "indicator": parent_event.value,
        "source_url": source_url,
        "spiderfoot_parity": True,
    }
    return [
        _make_event(
            event_type=malicious_type,
            value=value,
            slug=slug,
            parent_event=parent_event,
            ctx=ctx,
            risk_score=risk_score,
            confidence=confidence,
            tags=tags + ["malicious"],
            raw_payload=raw_payload,
        ),
        _make_event(
            event_type=blacklisted_type,
            value=value,
            slug=slug,
            parent_event=parent_event,
            ctx=ctx,
            risk_score=risk_score,
            confidence=confidence,
            tags=tags + ["blacklisted"],
            raw_payload=raw_payload,
        ),
    ]


def _parse_ip_lines(content: str, *, split_port: bool = False) -> set[str]:
    ips: set[str] = set()
    for line in content.splitlines():
        row = line.strip()
        if not row or row.startswith("#"):
            continue
        candidate = row.split(":", 1)[0] if split_port and row.count(":") == 1 else row
        candidate = candidate.strip()
        if _valid_ip(candidate):
            ips.add(candidate)
    return ips


def _parse_csv_first_column(content: str) -> set[str]:
    indicators: set[str] = set()
    for line in content.splitlines():
        row = line.strip()
        if not row or row.startswith("#"):
            continue
        candidate = row.split(",", 1)[0].strip().lower()
        if candidate:
            indicators.add(candidate)
    return indicators


def _parse_host_lines(content: str) -> set[str]:
    hosts: set[str] = set()
    for line in content.splitlines():
        row = line.strip().lower()
        if not row or row.startswith("#"):
            continue
        candidate = _hostname(row)
        if candidate and ("." in candidate or _valid_ip(candidate)):
            hosts.add(candidate)
    return hosts


def _parse_url_hosts(content: str) -> set[str]:
    hosts: set[str] = set()
    for line in content.splitlines():
        row = line.strip().lower()
        if not row or not row.startswith("http"):
            continue
        host = _hostname(row)
        if host and ("." in host or _valid_ip(host)):
            hosts.add(host)
    return hosts


class PlainIpFeedModule(BaseModule):
    """Base for SpiderFoot modules that compare an IP against a plain feed."""

    source_url = ""
    source_label = ""
    value_template = "{label} [{indicator}]\n<SFURL>{url}</SFURL>"
    split_port = False

    watched_types = {"ip"}
    produced_types = {"malicious_ip", "blacklisted_ip"}
    requires_key = False
    affiliate_setting_key = "check_affiliates"
    netblock_setting_key = "check_netblocks"
    affiliate_setting_default = True
    netblock_setting_default = True

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        if event.event_type == "affiliate_ipaddr" and not _module_bool(
            ctx,
            self.slug,
            _cti_slug(self.slug),
            self.affiliate_setting_key,
            self.affiliate_setting_default,
        ):
            return
        if event.event_type == "netblock_ownership" and not _module_bool(
            ctx,
            self.slug,
            _cti_slug(self.slug),
            self.netblock_setting_key,
            self.netblock_setting_default,
        ):
            return
        timeout = _http_timeout(ctx)
        content = _fetch_text(self.source_url, timeout, ctx, self.slug)
        if content is None:
            return

        for child in self._events_from_feed(content, event, ctx):
            yield child

    def _parse_feed(self, content: str) -> set[str]:
        return _parse_ip_lines(content, split_port=self.split_port)

    def _matched_indicator(self, content: str, parent_event: ScanEvent) -> str | None:
        indicators = self._parse_feed(content)
        if parent_event.event_type == "netblock_ownership":
            network = _parse_network(parent_event.value)
            if network is None:
                return None
            for indicator in indicators:
                try:
                    if ipaddress.ip_address(indicator) in network:
                        return indicator
                except ValueError:
                    continue
            return None

        indicator = parent_event.value.strip()
        if indicator in indicators:
            return indicator
        return None

    def _events_from_feed(self, content: str, parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        matched_indicator = self._matched_indicator(content, parent_event)
        if not matched_indicator:
            return []
        source_url = self._source_url_for(matched_indicator)
        value = self.value_template.format(
            label=self.source_label,
            indicator=parent_event.value.strip(),
            url=source_url,
        )
        return _emit_malicious_and_blacklisted(
            parent_event=parent_event,
            ctx=ctx,
            slug=self.slug,
            value=value,
            source_url=source_url,
            tags=[self.slug, "spiderfoot-feed", parent_event.event_type],
        )

    def _source_url_for(self, indicator: str) -> str:
        return self.source_url


class BlocklistDeModule(PlainIpFeedModule):
    slug = "blocklistde"
    name = "blocklist.de"
    watched_types = {"ip", "ipv6", "affiliate_ipaddr", "netblock_ownership"}
    source_url = "https://lists.blocklist.de/lists/all.txt"
    source_label = "blocklist.de"


class CinsScoreModule(PlainIpFeedModule):
    slug = "cinsscore"
    name = "CINS Army List"
    watched_types = {"ip", "affiliate_ipaddr", "netblock_ownership"}
    source_url = "https://cinsscore.com/list/ci-badguys.txt"
    source_label = "cinsscore.com"


class EmergingThreatsModule(PlainIpFeedModule):
    slug = "emergingthreats"
    name = "Emerging Threats"
    watched_types = {"ip", "affiliate_ipaddr", "netblock_ownership"}
    source_url = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
    source_label = "EmergingThreats.net"


class GreenSnowModule(PlainIpFeedModule):
    slug = "greensnow"
    name = "Greensnow"
    watched_types = {"ip", "affiliate_ipaddr", "netblock_ownership"}
    source_url = "https://blocklist.greensnow.co/greensnow.txt"
    source_label = "greensnow.co"

    def _source_url_for(self, indicator: str) -> str:
        return f"https://greensnow.co/view/{indicator}"


class MultiProxyModule(PlainIpFeedModule):
    slug = "multiproxy"
    name = "multiproxy.org Open Proxies"
    watched_types = {"ip", "affiliate_ipaddr", "netblock_ownership"}
    source_url = "http://multiproxy.org/txt_all/proxy.txt"
    source_label = "multiproxy.org Open Proxies"
    split_port = True
    netblock_setting_key = ("check_netblocks", "lookup_netblock_ips", "netblocklookup")
    netblock_setting_default = False


class IndicatorFeedModule(BaseModule):
    """Base for SpiderFoot-style indicator list modules."""

    source_url = ""
    source_label = ""
    watched_types = {"domain", "internet_name"}
    produced_types = {
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
    malicious_only = False

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        if event.event_type in {"affiliate_internet_name", "affiliate_ipaddr"} and not _module_bool(
            ctx,
            self.slug,
            _cti_slug(self.slug),
            "check_affiliates",
            True,
        ):
            return
        if event.event_type == "co_hosted_site" and not _module_bool(
            ctx,
            self.slug,
            _cti_slug(self.slug),
            "check_cohosts",
            True,
        ):
            return
        timeout = _http_timeout(ctx)
        content = _fetch_text(self.source_url, timeout, ctx, self.slug)
        if content is None:
            return

        for child in self._events_from_feed(content, event, ctx):
            yield child

    def _parse_feed(self, content: str) -> set[str]:
        return _parse_host_lines(content)

    def _lookup_value(self, event: ScanEvent) -> str:
        return _target_indicator(event)

    def _event_value(self, event: ScanEvent, source_url: str) -> str:
        return f"{self.source_label} [{event.value}]\n<SFURL>{source_url}</SFURL>"

    def _events_from_feed(self, content: str, parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        indicator = self._lookup_value(parent_event)
        if not indicator or indicator not in self._parse_feed(content):
            return []

        value = self._event_value(parent_event, self.source_url)
        if self.malicious_only:
            malicious_type, _ = _event_pair_for(parent_event.event_type)
            return [
                _make_event(
                    event_type=malicious_type,
                    value=value,
                    slug=self.slug,
                    parent_event=parent_event,
                    ctx=ctx,
                    risk_score=85,
                    confidence=85,
                    tags=[self.slug, "spiderfoot-feed", "malicious"],
                    raw_payload={
                        "indicator": parent_event.value,
                        "source_url": self.source_url,
                        "spiderfoot_parity": True,
                    },
                )
            ]

        return _emit_malicious_and_blacklisted(
            parent_event=parent_event,
            ctx=ctx,
            slug=self.slug,
            value=value,
            source_url=self.source_url,
            tags=[self.slug, "spiderfoot-feed"],
        )


class BotvrijModule(IndicatorFeedModule):
    slug = "botvrij"
    name = "botvrij.eu"
    watched_types = {"domain", "internet_name", "affiliate_internet_name", "co_hosted_site"}
    source_url = "https://www.botvrij.eu/data/blocklist/blocklist_full.csv"
    source_label = "botvrij.eu Domain Blocklist"

    def _parse_feed(self, content: str) -> set[str]:
        return _parse_csv_first_column(content)


class CoinBlockerModule(IndicatorFeedModule):
    slug = "coinblocker"
    name = "CoinBlocker Lists"
    watched_types = {"domain", "internet_name", "affiliate_internet_name", "co_hosted_site"}
    source_url = "https://zerodot1.gitlab.io/CoinBlockerLists/list.txt"
    source_label = "CoinBlocker"


class CyberCrimeTrackerModule(IndicatorFeedModule):
    slug = "cybercrimetracker"
    name = "CyberCrime-Tracker.net"
    watched_types = {"domain", "internet_name", "ip", "affiliate_internet_name", "affiliate_ipaddr", "co_hosted_site"}
    source_url = "https://cybercrime-tracker.net/all.php"
    source_label = "CyberCrime-Tracker.net Malicious Submissions"

    def _parse_feed(self, content: str) -> set[str]:
        indicators: set[str] = set()
        for line in content.splitlines():
            row = line.strip().lower()
            if not row or row.startswith("#"):
                continue
            host = row.split("/", 1)[0].split(":", 1)[0].strip()
            if host and "." in host:
                indicators.add(host)
        return indicators

    def _event_value(self, event: ScanEvent, source_url: str) -> str:
        url = f"https://cybercrime-tracker.net/index.php?search={urllib.parse.quote(event.value)}"
        return f"{self.source_label} [{event.value}]\n<SFURL>{url}</SFURL>"


class StevenBlackHostsModule(IndicatorFeedModule):
    slug = "stevenblackhosts"
    name = "Steven Black Hosts"
    watched_types = {"domain", "internet_name", "affiliate_internet_name", "co_hosted_site"}
    source_url = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
    source_label = "Steven Black Hosts Blocklist"

    def _parse_feed(self, content: str) -> set[str]:
        hosts: set[str] = set()
        for line in content.splitlines():
            row = line.strip().lower()
            if not row or row.startswith("#"):
                continue
            parts = row.split()
            if len(parts) < 2:
                continue
            host = parts[1].strip()
            if host and "." in host:
                hosts.add(host)
        return hosts


class VxVaultModule(IndicatorFeedModule):
    slug = "vxvault"
    name = "VXVault.net"
    watched_types = {"domain", "internet_name", "ip", "ipv6", "affiliate_internet_name", "affiliate_ipaddr", "co_hosted_site"}
    produced_types = {
        "malicious_internet_name",
        "malicious_ip",
        "malicious_affiliate_internet_name",
        "malicious_affiliate_ipaddr",
        "malicious_cohost",
    }
    source_url = "http://vxvault.net/URL_List.php"
    source_label = "VXVault Malicious URL List"
    malicious_only = True

    def _parse_feed(self, content: str) -> set[str]:
        return _parse_url_hosts(content)


class DnsblModule(BaseModule):
    slug = "dnsbl"
    name = "DNSBL"
    watched_types = {"ip"}
    produced_types = {"malicious_ip", "blacklisted_ip"}
    requires_key = False

    def _resolve(self, lookup: str) -> list[str]:
        try:
            return list(dict.fromkeys(socket.gethostbyname_ex(lookup)[2]))
        except Exception:
            return []

    def _dnsbl_events(
        self,
        *,
        parent_event: ScanEvent,
        ctx,
        value: str,
        source_url: str,
        result_label: str,
        emit_malicious: bool = True,
    ) -> list[ScanEvent]:
        events = []
        _, blacklisted_type = _event_pair_for(parent_event.event_type)
        events.append(_make_event(
            event_type=blacklisted_type,
            value=value,
            slug=self.slug,
            parent_event=parent_event,
            ctx=ctx,
            risk_score=75,
            confidence=85,
            tags=[self.slug, "dnsbl", "blacklisted"],
            raw_payload={
                "indicator": parent_event.value,
                "source_url": source_url,
                "result": result_label,
                "spiderfoot_parity": True,
            },
        ))
        if emit_malicious:
            malicious_type, _ = _event_pair_for(parent_event.event_type)
            events.append(_make_event(
                event_type=malicious_type,
                value=value,
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=85,
                confidence=85,
                tags=[self.slug, "dnsbl", "malicious"],
                raw_payload={
                    "indicator": parent_event.value,
                    "source_url": source_url,
                    "result": result_label,
                    "spiderfoot_parity": True,
                },
            ))
        return events


class SpamHausZenModule(DnsblModule):
    slug = "spamhaus"
    name = "Spamhaus Zen"
    watched_types = {"ip", "affiliate_ipaddr", "netblock_ownership", "netblock_member"}
    checks = {
        "127.0.0.2": "Spamhaus (Zen) - Spammer",
        "127.0.0.3": "Spamhaus (Zen) - Spammer",
        "127.0.0.4": "Spamhaus (Zen) - Proxies, Trojans, etc.",
        "127.0.0.5": "Spamhaus (Zen) - Proxies, Trojans, etc.",
        "127.0.0.6": "Spamhaus (Zen) - Proxies, Trojans, etc.",
        "127.0.0.7": "Spamhaus (Zen) - Proxies, Trojans, etc.",
        "127.0.0.10": "Spamhaus (Zen) - Potential Spammer",
        "127.0.0.11": "Spamhaus (Zen) - Potential Spammer",
    }

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        for address in _dnsbl_query_targets(event, ctx, self.slug):
            reversed_ip = _reverse_ipv4(address)
            if not reversed_ip:
                continue
            lookup = f"{reversed_ip}.zen.spamhaus.org"
            for result in self._resolve(lookup):
                if result == "127.255.255.252":
                    ctx.error("Spamhaus rejected malformed request.", self.slug)
                    continue
                if result == "127.255.255.254":
                    ctx.error("Spamhaus denied query via public/open resolver.", self.slug)
                    continue
                if result == "127.255.255.255":
                    ctx.error("Spamhaus rejected query due to excessive number of queries.", self.slug)
                    continue
                if result not in self.checks:
                    continue
                value = f"{self.checks[result]} [{address}]"
                for child in self._dnsbl_events(
                    parent_event=event,
                    ctx=ctx,
                    value=value,
                    source_url="https://www.spamhaus.org/zen/",
                    result_label=result,
                ):
                    yield child


class SpamCopModule(DnsblModule):
    slug = "spamcop"
    name = "SpamCop"
    watched_types = {"ip", "affiliate_ipaddr", "netblock_ownership", "netblock_member"}

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        for address in _dnsbl_query_targets(event, ctx, self.slug):
            reversed_ip = _reverse_ipv4(address)
            if not reversed_ip:
                continue
            lookup = f"{reversed_ip}.bl.spamcop.net"
            for result in self._resolve(lookup):
                if result != "127.0.0.2":
                    continue
                url = f"https://www.spamcop.net/w3m?action=checkblock&ip={address}"
                value = f"SpamCop Blacklist [{address}]\n<SFURL>{url}</SFURL>"
                for child in self._dnsbl_events(
                    parent_event=event,
                    ctx=ctx,
                    value=value,
                    source_url=url,
                    result_label=result,
                ):
                    yield child


class DroneBlModule(DnsblModule):
    slug = "dronebl"
    name = "DroneBL"
    watched_types = {"ip", "affiliate_ipaddr", "netblock_ownership"}
    produced_types = {"malicious_ip", "blacklisted_ip", "vpn_host", "proxy_host"}
    checks = {
        "127.0.0.3": "dronebl.org - IRC Drone",
        "127.0.0.5": "dronebl.org - Bottler",
        "127.0.0.6": "dronebl.org - Unknown spambot or drone",
        "127.0.0.7": "dronebl.org - DDOS Drone",
        "127.0.0.8": "dronebl.org - SOCKS Proxy",
        "127.0.0.9": "dronebl.org - HTTP Proxy",
        "127.0.0.10": "dronebl.org - ProxyChain",
        "127.0.0.11": "dronebl.org - Web Page Proxy",
        "127.0.0.12": "dronebl.org - Open DNS Resolver",
        "127.0.0.13": "dronebl.org - Brute force attackers",
        "127.0.0.14": "dronebl.org - Open Wingate Proxy",
        "127.0.0.15": "dronebl.org - Compromised router / gateway",
        "127.0.0.16": "dronebl.org - Autorooting worms",
        "127.0.0.17": "dronebl.org - Automatically determined botnet IPs (experimental)",
        "127.0.0.18": "dronebl.org - Possibly compromised DNS/MX",
        "127.0.0.19": "dronebl.org - Abused VPN Service",
        "127.0.0.255": "dronebl.org - Unknown",
    }
    malicious_codes = {
        "127.0.0.3",
        "127.0.0.5",
        "127.0.0.6",
        "127.0.0.7",
        "127.0.0.13",
        "127.0.0.15",
        "127.0.0.16",
        "127.0.0.17",
        "127.0.0.18",
        "127.0.0.19",
    }
    proxy_codes = {"127.0.0.8", "127.0.0.9", "127.0.0.10", "127.0.0.11", "127.0.0.14"}

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        if event.event_type == "affiliate_ipaddr" and not _module_bool(
            ctx,
            self.slug,
            _cti_slug(self.slug),
            "check_affiliates",
            True,
        ):
            return

        addresses = [event.value]
        if event.event_type == "netblock_ownership":
            if not _module_bool(ctx, self.slug, _cti_slug(self.slug), "lookup_netblock_ips", True):
                return
            network = _parse_network(event.value)
            if network is None or network.version != 4:
                return
            max_size = int(_module_setting(ctx, self.slug, _cti_slug(self.slug), "max_netblock_size", 24) or 24)
            if network.prefixlen < max_size:
                ctx.debug(
                    f"Network size bigger than permitted: {network.prefixlen} > {max_size}",
                    self.slug,
                )
                return
            addresses = [str(address) for address in network]

        for address in addresses:
            reversed_ip = _reverse_ipv4(address)
            if not reversed_ip:
                continue
            lookup = f"{reversed_ip}.dnsbl.dronebl.org"
            for result in self._resolve(lookup):
                if result not in self.checks:
                    continue
                value = f"{self.checks[result]} [{address}]"
                for child in self._dnsbl_events(
                    parent_event=event,
                    ctx=ctx,
                    value=value,
                    source_url="https://dronebl.org/",
                    result_label=result,
                    emit_malicious=result in self.malicious_codes,
                ):
                    yield child
                if result in self.proxy_codes:
                    yield _make_event(
                        event_type="proxy_host",
                        value=address,
                        slug=self.slug,
                        parent_event=event,
                        ctx=ctx,
                        risk_score=50,
                        confidence=85,
                        tags=[self.slug, "proxy"],
                        raw_payload={"result": result, "spiderfoot_parity": True},
                    )
                if result == "127.0.0.19":
                    yield _make_event(
                        event_type="vpn_host",
                        value=address,
                        slug=self.slug,
                        parent_event=event,
                        ctx=ctx,
                        risk_score=40,
                        confidence=85,
                        tags=[self.slug, "vpn"],
                        raw_payload={"result": result, "spiderfoot_parity": True},
                    )


class UceProtectModule(DnsblModule):
    slug = "uceprotect"
    name = "UCEPROTECT"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        reversed_ip = _reverse_ipv4(event.value)
        if not reversed_ip:
            return
        checks = [
            (f"{reversed_ip}.dnsbl-1.uceprotect.net", "UCEPROTECT - Level 1 (high likelihood)"),
            (f"{reversed_ip}.dnsbl-2.uceprotect.net", "UCEPROTECT - Level 2 (some false positives)"),
        ]
        url = f"https://www.uceprotect.net/en/rblcheck.php?ipr={event.value}"
        for lookup, label in checks:
            results = self._resolve(lookup)
            if not results:
                continue
            value = f"{label} [{event.value}]\n<SFURL>{url}</SFURL>"
            for child in self._dnsbl_events(
                parent_event=event,
                ctx=ctx,
                value=value,
                source_url=url,
                result_label=",".join(results),
            ):
                yield child


class SurblModule(DnsblModule):
    slug = "surbl"
    name = "SURBL"
    watched_types = {
        "domain",
        "internet_name",
        "ip",
        "affiliate_ipaddr",
        "netblock_ownership",
        "netblock_member",
        "affiliate_internet_name",
        "co_hosted_site",
    }
    produced_types = {
        "malicious_internet_name",
        "blacklisted_internet_name",
        "malicious_ip",
        "blacklisted_ip",
        "malicious_affiliate_ipaddr",
        "blacklisted_affiliate_ipaddr",
        "malicious_affiliate_internet_name",
        "blacklisted_affiliate_internet_name",
        "malicious_cohost",
        "blacklisted_cohost",
        "malicious_netblock",
        "blacklisted_netblock",
        "malicious_subnet",
        "blacklisted_subnet",
    }

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        query_targets = _dnsbl_query_targets(
            event,
            ctx,
            self.slug,
            affiliate_keys="check_affiliates",
        ) if event.event_type in {"affiliate_ipaddr", "netblock_ownership", "netblock_member", "ip"} else [event.value.strip().lower()]
        if event.event_type == "affiliate_internet_name" and not _module_bool(
            ctx,
            self.slug,
            _cti_slug(self.slug),
            "check_affiliates",
            True,
        ):
            return
        if event.event_type == "co_hosted_site" and not _module_bool(
            ctx,
            self.slug,
            _cti_slug(self.slug),
            "check_cohosts",
            True,
        ):
            return

        for target in query_targets:
            if _valid_ipv4(target):
                reversed_ip = _reverse_ipv4(target)
                if not reversed_ip:
                    continue
                lookup = f"{reversed_ip}.multi.surbl.org"
            else:
                lookup = f"{target.strip().lower()}.multi.surbl.org"

            for result in self._resolve(lookup):
                if not result.startswith("127.0.0."):
                    continue
                if result == "127.0.0.1":
                    ctx.error("SURBL rejected lookup request.", self.slug)
                    continue
                value = f"SURBL [{target}]"
                for child in self._dnsbl_events(
                    parent_event=event,
                    ctx=ctx,
                    value=value,
                    source_url="http://www.surbl.org/",
                    result_label=result,
                ):
                    yield child


class TorExitNodesModule(BaseModule):
    slug = "torexits"
    name = "TOR Exit Nodes"
    watched_types = {"ip", "ipv6", "affiliate_ipaddr", "netblock_ownership"}
    produced_types = {"ip", "ipv6", "tor_exit_node"}
    requires_key = False
    source_url = "https://onionoo.torproject.org/details?search=flag:exit"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        if event.event_type == "affiliate_ipaddr" and not _module_bool(
            ctx,
            self.slug,
            _cti_slug(self.slug),
            "check_affiliates",
            True,
        ):
            return
        if event.event_type == "netblock_ownership" and not _module_bool(
            ctx,
            self.slug,
            _cti_slug(self.slug),
            "check_netblocks",
            True,
        ):
            return
        timeout = _http_timeout(ctx)
        content = _fetch_text(self.source_url, timeout, ctx, self.slug, accept="application/json, */*")
        if content is None:
            return
        exit_nodes = self._parse_exit_nodes(content)

        addresses = [event.value]
        if event.event_type == "netblock_ownership":
            network = _parse_network(event.value)
            if network is None:
                return
            addresses = [str(address) for address in network]

        for address in addresses:
            if address not in exit_nodes:
                continue
            parent_event = event
            if event.event_type == "netblock_ownership":
                ip_event_type = "ipv6" if ":" in address else "ip"
                parent_event = _make_event(
                    event_type=ip_event_type,
                    value=address,
                    slug=self.slug,
                    parent_event=event,
                    ctx=ctx,
                    risk_score=0,
                    confidence=90,
                    tags=[self.slug, "tor", "candidate"],
                    raw_payload={
                        "indicator": event.value,
                        "source_url": self.source_url,
                        "spiderfoot_parity": True,
                    },
                )
                yield parent_event
            yield _make_event(
                event_type="tor_exit_node",
                value=address,
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=35,
                confidence=90,
                tags=[self.slug, "tor", "exit-node"],
                raw_payload={
                    "indicator": event.value,
                    "source_url": self.source_url,
                    "spiderfoot_parity": True,
                },
            )

    def _parse_exit_nodes(self, content: str) -> set[str]:
        try:
            payload = json.loads(content)
        except Exception:
            return set()

        ips: set[str] = set()
        relays = payload.get("relays")
        if not isinstance(relays, list):
            return ips

        for relay in relays:
            if not isinstance(relay, dict):
                continue
            or_addresses = relay.get("or_addresses")
            if isinstance(or_addresses, list):
                for address in or_addresses:
                    value = str(address or "")
                    if value.startswith("[") and "]" in value:
                        candidate = value.split("[", 1)[1].split("]", 1)[0]
                    else:
                        candidate = value.split(":", 1)[0]
                    if _valid_ip(candidate):
                        ips.add(candidate)

            exit_addresses = relay.get("exit_addresses")
            if isinstance(exit_addresses, list):
                for address in exit_addresses:
                    candidate = str(address or "").strip()
                    if _valid_ip(candidate):
                        ips.add(candidate)

        return ips


class Base64DecoderModule(BaseModule):
    slug = "base64"
    name = "Base64 Decoder"
    watched_types = {"linked_url_internal"}
    produced_types = {"base64_data"}
    requires_key = False
    pattern = re.compile(r"([A-Za-z0-9+/]+={1,2})")

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        if event.event_type != "linked_url_internal":
            return

        min_length = _module_int(ctx, self.slug, "base64-decoder", ("minlength", "min_length"), 10)
        decoded_data = urllib.parse.unquote(event.value)
        for match in self.pattern.findall(decoded_data):
            if len(match) < min_length:
                continue
            caps = sum(1 for char in match if char.isupper())
            if caps < (min_length / 4):
                continue
            try:
                decoded = base64.b64decode(match).decode("utf-8")
            except Exception:
                continue
            yield _make_event(
                event_type="base64_data",
                value=f"{match} ({decoded})",
                slug=self.slug,
                parent_event=event,
                ctx=ctx,
                risk_score=0,
                confidence=80,
                tags=[self.slug, "content-analysis"],
                raw_payload={"source": event.value, "spiderfoot_parity": True},
            )


class SimpleAdblockRules:
    """Small EasyList matcher used only when adblockparser is unavailable."""

    def __init__(self, lines: Iterable[str]) -> None:
        self.rules = [line.strip() for line in lines if self._keep(line)]

    def should_block(self, url: str, _options: dict[str, Any] | None = None) -> bool:
        parsed = urllib.parse.urlparse(url)
        host = str(parsed.hostname or "").lower()
        normalized_url = url.lower()
        for rule in self.rules:
            core = rule.split("$", 1)[0].strip().lower()
            if not core:
                continue
            if core.startswith("||"):
                domain = core[2:].split("^", 1)[0].split("/", 1)[0].strip(".")
                if domain and (host == domain or host.endswith("." + domain)):
                    return True
                continue
            needle = core.strip("|").replace("^", "").replace("*", "")
            if needle and needle in normalized_url:
                return True
        return False

    def _keep(self, line: str) -> bool:
        row = line.strip()
        return bool(row and not row.startswith(("!", "@@", "[")))


class AdBlockCheckModule(BaseModule):
    slug = "adblock"
    name = "AdBlock Check"
    watched_types = {"linked_url_internal", "linked_url_external", "provider_javascript"}
    produced_types = {"url_adblocked_internal", "url_adblocked_external"}
    requires_key = False
    default_blocklist = "https://easylist-downloads.adblockplus.org/easylist.txt"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        blocklist_url = str(
            _module_setting(ctx, self.slug, _cti_slug(self.slug), ("blocklist", "blocklist_url"), self.default_blocklist)
            or self.default_blocklist
        )
        timeout = max(30, _http_timeout(ctx, 30))
        content = _fetch_text(blocklist_url, timeout, ctx, self.slug)
        if content is None:
            return
        rules = self._rules_from_content(content, ctx)
        url = event.value
        try:
            if event.event_type == "provider_javascript":
                should_block = bool(rules.should_block(url, {"third-party": True, "script": True}))
                event_type = "url_adblocked_external"
            elif event.event_type == "linked_url_external":
                should_block = bool(rules.should_block(url, {"third-party": True}))
                event_type = "url_adblocked_external"
            elif event.event_type == "linked_url_internal":
                should_block = bool(rules.should_block(url))
                event_type = "url_adblocked_internal"
            else:
                return
        except ValueError as exc:
            ctx.error(f"Parsing error handling AdBlock list: {exc}", self.slug)
            return

        if not should_block:
            return

        yield _make_event(
            event_type=event_type,
            value=url,
            slug=self.slug,
            parent_event=event,
            ctx=ctx,
            risk_score=5,
            confidence=80,
            tags=[self.slug, "adblock"],
            raw_payload={
                "source_url": blocklist_url,
                "spiderfoot_parity": True,
            },
        )

    def _rules_from_content(self, content: str, ctx):
        lines = content.splitlines()
        if adblockparser is not None:
            try:
                return adblockparser.AdblockRules(lines)
            except Exception as exc:
                ctx.warning(f"AdBlock parser failed, using fallback matcher: {exc}", self.slug)
        return SimpleAdblockRules(lines)


class ZoneHModule(BaseModule):
    slug = "zoneh"
    name = "Zone-H Defacement Check"
    watched_types = {"domain", "internet_name", "ip", "ipv6", "affiliate_internet_name", "affiliate_ipaddr", "co_hosted_site"}
    produced_types = {
        "defaced_internet_name",
        "defaced_ip",
        "defaced_affiliate_internet_name",
        "defaced_affiliate_ipaddr",
        "defaced_cohost",
    }
    requires_key = False
    source_url = "https://www.zone-h.org/rss/specialdefacements"
    rss_pattern = re.compile(
        r"<title><!\[CDATA\[(.[^\]]*)\]\]></title>\s+<link><!\[CDATA\[(.[^\]]*)\]\]></link>",
        re.I,
    )

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        if event.event_type == "co_hosted_site" and not _module_bool(
            ctx,
            self.slug,
            _cti_slug(self.slug),
            "check_cohosts",
            True,
        ):
            return
        if event.event_type in {"affiliate_internet_name", "affiliate_ipaddr"} and not _module_bool(
            ctx,
            self.slug,
            _cti_slug(self.slug),
            "check_affiliates",
            True,
        ):
            return
        timeout = _http_timeout(ctx)
        content = _fetch_text(self.source_url, timeout, ctx, self.slug, accept="application/rss+xml, text/xml, */*")
        if content is None:
            return
        value = self._lookup_item(event.value, content)
        if not value:
            return
        event_type = "defaced_internet_name"
        if event.event_type in {"ip", "ipv6"}:
            event_type = "defaced_ip"
        elif event.event_type == "affiliate_internet_name":
            event_type = "defaced_affiliate_internet_name"
        elif event.event_type == "affiliate_ipaddr":
            event_type = "defaced_affiliate_ipaddr"
        elif event.event_type == "co_hosted_site":
            event_type = "defaced_cohost"
        yield _make_event(
            event_type=event_type,
            value=value,
            slug=self.slug,
            parent_event=event,
            ctx=ctx,
            risk_score=55,
            confidence=80,
            tags=[self.slug, "defacement"],
            raw_payload={
                "indicator": event.value,
                "source_url": self.source_url,
                "spiderfoot_parity": True,
            },
        )

    def _lookup_item(self, target: str, content: str) -> str | None:
        for title, link in self.rss_pattern.findall(content):
            if target in title:
                return f"{title}\n<SFURL>{link}</SFURL>"
        return None


class ThreatMinerModule(BaseModule):
    slug = "threatminer"
    name = "ThreatMiner"
    watched_types = {"domain", "ip", "netblock_ownership", "netblock_member"}
    produced_types = {"internet_name", "internet_name_unresolved", "co_hosted_site"}
    requires_key = False
    base_url = "https://api.threatminer.org"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        timeout = _http_timeout(ctx, 10)
        if event.event_type == "domain":
            payload = self._fetch_payload(event.value, "subs", timeout, ctx)
            if payload is None:
                return
            for child in self._domain_events(payload, event, ctx):
                yield child
            return

        query_targets = _dnsbl_query_targets(
            event,
            ctx,
            self.slug,
            affiliate_keys=None,
            netblock_default=False,
            subnet_default=False,
        )
        verify = _module_bool(ctx, self.slug, _cti_slug(self.slug), "verify", True)
        max_cohosts = _module_int(ctx, self.slug, _cti_slug(self.slug), ("maxcohost", "max_cohosts"), 100)
        age_limit_days = _module_int(ctx, self.slug, _cti_slug(self.slug), "age_limit_days", 90)
        cohost_count = 0

        for target in query_targets:
            payload = self._fetch_payload(target, "passive", timeout, ctx)
            if payload is None:
                continue
            children = self._ip_events(
                payload,
                event,
                ctx,
                verify=verify,
                max_cohosts=max_cohosts,
                age_limit_days=age_limit_days,
                cohost_count=cohost_count,
            )
            cohost_count += sum(1 for child in children if child.event_type == "co_hosted_site")
            for child in children:
                yield child

    def _fetch_payload(self, value: str, query_type: str, timeout: int, ctx) -> dict[str, Any] | None:
        target_kind = "host" if _valid_ip(value) else "domain"
        rt = 5 if query_type == "subs" else 2
        url = f"{self.base_url}/v2/{target_kind}.php?q={urllib.parse.quote(value)}&rt={rt}"
        content = _fetch_text(url, timeout, ctx, self.slug, accept="application/json, */*")
        if content is None:
            return None
        try:
            payload = json.loads(content)
        except Exception as exc:
            ctx.error(f"Error processing JSON response from ThreatMiner: {exc}", self.slug)
            return None
        return payload if isinstance(payload, dict) else None

    def _domain_events(self, payload: dict[str, Any], parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        results = payload.get("results")
        if not isinstance(results, list):
            return []

        events: list[ScanEvent] = []
        seen: set[str] = set()
        for host in results:
            value = str(host or "").strip().lower()
            if not value or value in seen:
                continue
            seen.add(value)
            events.append(_make_event(
                event_type="internet_name",
                value=value,
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=0,
                confidence=80,
                tags=[self.slug, "subdomain"],
                raw_payload={"source": "ThreatMiner", "spiderfoot_parity": True},
            ))
        return events

    def _ip_events(
        self,
        payload: dict[str, Any],
        parent_event: ScanEvent,
        ctx,
        *,
        verify: bool = True,
        max_cohosts: int = 100,
        age_limit_days: int = 90,
        cohost_count: int = 0,
    ) -> list[ScanEvent]:
        results = payload.get("results")
        if not isinstance(results, list):
            return []

        events: list[ScanEvent] = []
        seen: set[str] = set()
        for row in results:
            if not isinstance(row, dict):
                continue
            host = str(row.get("domain", "") or "").strip().lower()
            if not host or host in seen:
                continue
            if host == parent_event.value.strip().lower():
                continue
            if self._is_too_old(row.get("last_seen"), age_limit_days):
                continue
            seen.add(host)
            if _matches_root_target(host, ctx.root_target):
                event_type = "internet_name"
                if verify and not _host_resolves(host):
                    event_type = "internet_name_unresolved"
                events.append(_make_event(
                    event_type=event_type,
                    value=host,
                    slug=self.slug,
                    parent_event=parent_event,
                    ctx=ctx,
                    risk_score=0,
                    confidence=80,
                    tags=[self.slug, "passive-dns"],
                    raw_payload={"source": "ThreatMiner", "spiderfoot_parity": True},
                ))
                continue
            if cohost_count >= max_cohosts:
                continue
            events.append(_make_event(
                event_type="co_hosted_site",
                value=host,
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=0,
                confidence=75,
                tags=[self.slug, "passive-dns"],
                raw_payload={"source": "ThreatMiner", "spiderfoot_parity": True},
            ))
            cohost_count += 1
        return events

    def _is_too_old(self, last_seen: Any, age_limit_days: int = 90) -> bool:
        value = str(last_seen or "").strip()
        if not value:
            return True
        try:
            parsed = datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except ValueError:
            return True
        if age_limit_days <= 0:
            return False
        age_days = (datetime.now(timezone.utc) - parsed).days
        return age_days > age_limit_days
