"""abuse.ch module for the first-party CTI engine."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, AsyncIterator

from ..events import ScanEvent
from ..module_base import BaseModule


class AbuseChModule(BaseModule):
    slug = "abuse-ch"
    name = "abuse.ch"
    watched_types = {"hash", "url", "domain", "ip"}
    produced_types = {
        "linked_url_internal",
        "internet_name",
        "malicious_internet_name",
        "malicious_ip",
        "malicious_url",
        "malicious_hash",
    }
    requires_key = False

    MALWARE_BAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"
    URLHAUS_URL_API = "https://urlhaus-api.abuse.ch/v1/url/"
    URLHAUS_HOST_API = "https://urlhaus-api.abuse.ch/v1/host/"
    FEODO_TRACKER_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
    SSLBL_URL = "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv"
    URLHAUS_RECENT_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        timeout = int(ctx.request.settings.global_settings.get("http_timeout", 15) or 15)

        if event.event_type in {"domain", "ip"}:
            matches = self._fetch_spiderfoot_blacklist_matches(event.event_type, event.value, timeout, ctx)
            for child in self._blacklist_match_events(matches, event, ctx):
                yield child
            return

        api_config = ctx.api_config_for(self.slug)
        api_key = str(api_config.get("api_key", "")).strip()
        if not api_key:
            ctx.error("abuse.ch module requires an Auth-Key for URL and hash lookups.", self.slug)
            return

        payload = self._fetch_payload(event.event_type, event.value, api_key, timeout, ctx)
        if payload is None:
            return

        for child in self._events_from_payload(payload, event, ctx):
            yield child

    def _fetch_payload(
        self,
        event_type: str,
        value: str,
        api_key: str,
        timeout: int,
        ctx,
    ) -> dict[str, Any] | None:
        if event_type == "hash":
            endpoint = self.MALWARE_BAZAAR_URL
            body = urllib.parse.urlencode({"query": "get_info", "hash": value}).encode("utf-8")
        elif event_type == "url":
            endpoint = self.URLHAUS_URL_API
            body = urllib.parse.urlencode({"url": value}).encode("utf-8")
        elif event_type in {"domain", "ip"}:
            endpoint = self.URLHAUS_HOST_API
            body = urllib.parse.urlencode({"host": value}).encode("utf-8")
        else:
            ctx.debug(f"abuse.ch does not yet handle event type '{event_type}'.", self.slug)
            return None

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "User-Agent": "CTI Engine",
        }
        if api_key:
            headers["Auth-Key"] = api_key

        ctx.info(f"Fetching abuse.ch data for {value}.", self.slug)
        request = urllib.request.Request(endpoint, headers=headers, data=body, method="POST")

        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec - fixed provider URL
                status = int(getattr(response, "status", 200) or 200)
                content = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                ctx.info(f"abuse.ch has no data for {value}.", self.slug)
                return None
            if exc.code == 429:
                ctx.error("Your request to abuse.ch was throttled.", self.slug)
                return None
            if exc.code in (401, 403):
                ctx.error("abuse.ch rejected the API key or access token.", self.slug)
                return None
            ctx.warning(f"abuse.ch request failed for {value}: HTTP {exc.code}", self.slug)
            return None
        except Exception as exc:
            ctx.warning(f"abuse.ch request failed for {value}: {exc}", self.slug)
            return None

        if status >= 400:
            ctx.warning(f"abuse.ch returned HTTP {status} for {value}.", self.slug)
            return None

        try:
            decoded = json.loads(content)
        except json.JSONDecodeError as exc:
            ctx.error(f"abuse.ch returned invalid JSON: {exc}", self.slug)
            return None

        query_status = str(decoded.get("query_status", "") or "").strip().lower()
        if query_status in {"no_results", "hash_not_found"}:
            ctx.info(f"abuse.ch has no matching data for {value}.", self.slug)
            return None

        return decoded

    def _events_from_payload(
        self,
        payload: dict[str, Any],
        parent_event: ScanEvent,
        ctx,
    ) -> list[ScanEvent]:
        if parent_event.event_type == "hash":
            return self._hash_events(payload, parent_event, ctx)
        if parent_event.event_type == "url":
            return self._url_events(payload, parent_event, ctx)
        if parent_event.event_type in {"domain", "ip"}:
            return self._host_events(payload, parent_event, ctx)
        return []

    def _fetch_spiderfoot_blacklist_matches(
        self,
        target_type: str,
        value: str,
        timeout: int,
        ctx,
    ) -> list[dict[str, str]]:
        matches: list[dict[str, str]] = []

        if target_type == "ip":
            feodo = self._fetch_text(self.FEODO_TRACKER_URL, timeout, ctx)
            if feodo is not None and value in self._parse_feodo_blacklist(feodo):
                matches.append({
                    "name": "Abuse.ch Feodo Tracker",
                    "url": self.FEODO_TRACKER_URL,
                    "tag": "feodo",
                })

            sslbl = self._fetch_text(self.SSLBL_URL, timeout, ctx)
            if sslbl is not None and value in self._parse_sslbl_blacklist(sslbl):
                matches.append({
                    "name": "Abuse.ch SSL Blacklist",
                    "url": self.SSLBL_URL,
                    "tag": "sslbl",
                })

        if target_type in {"domain", "ip"}:
            urlhaus = self._fetch_text(self.URLHAUS_RECENT_URL, timeout, ctx)
            if urlhaus is not None:
                host_blacklist = self._parse_urlhaus_blacklist(urlhaus)
                indicator = value.strip().lower()
                if indicator in host_blacklist:
                    matches.append({
                        "name": "Abuse.ch URL Haus Blacklist",
                        "url": self.URLHAUS_RECENT_URL,
                        "tag": "urlhaus",
                    })

        return matches

    def _fetch_text(self, endpoint: str, timeout: int, ctx) -> str | None:
        request = urllib.request.Request(
            endpoint,
            headers={"Accept": "text/plain, text/csv, */*", "User-Agent": "CTI Engine"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec - fixed provider URL
                status = int(getattr(response, "status", 200) or 200)
                content = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            ctx.warning(f"abuse.ch blacklist request failed: HTTP {exc.code}", self.slug)
            return None
        except Exception as exc:
            ctx.warning(f"abuse.ch blacklist request failed: {exc}", self.slug)
            return None

        if status >= 400:
            ctx.warning(f"abuse.ch blacklist request returned HTTP {status}.", self.slug)
            return None

        return content

    def _parse_feodo_blacklist(self, content: str) -> set[str]:
        ips: set[str] = set()
        for line in content.splitlines():
            candidate = line.strip()
            if not candidate or candidate.startswith("#"):
                continue
            ips.add(candidate)
        return ips

    def _parse_sslbl_blacklist(self, content: str) -> set[str]:
        ips: set[str] = set()
        for line in content.splitlines():
            row = line.strip()
            if not row or row.startswith("#"):
                continue
            parts = row.split(",")
            if len(parts) < 2:
                continue
            ip_value = parts[1].strip()
            if ip_value:
                ips.add(ip_value)
        return ips

    def _parse_urlhaus_blacklist(self, content: str) -> set[str]:
        hosts: set[str] = set()
        for line in content.splitlines():
            row = line.strip().lower()
            if not row or row.startswith("#"):
                continue
            pieces = row.split("/")
            if len(pieces) < 3:
                continue
            host = pieces[2].split(":")[0].strip()
            if host and "." in host:
                hosts.add(host)
        return hosts

    def _blacklist_match_events(
        self,
        matches: list[dict[str, str]],
        parent_event: ScanEvent,
        ctx,
    ) -> list[ScanEvent]:
        event_type = "malicious_internet_name" if parent_event.event_type == "domain" else "malicious_ip"
        events: list[ScanEvent] = []
        for match in matches:
            label = match.get("name", "Abuse.ch Blacklist")
            tags = ["abuse-ch", "spiderfoot_blacklist", parent_event.event_type]
            tag_value = str(match.get("tag", "") or "").strip()
            if tag_value:
                tags.append(tag_value)
            events.append(ScanEvent(
                event_type=event_type,
                value=f"{parent_event.value} [{label}]",
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=85,
                visibility=100,
                risk_score=75,
                tags=tags,
                raw_payload={
                    "indicator": parent_event.value,
                    "source_list": label,
                    "source_url": match.get("url"),
                },
            ))
        return events

    def _hash_events(self, payload: dict[str, Any], parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        data_rows = payload.get("data") or []
        sample = data_rows[0] if isinstance(data_rows, list) and data_rows else {}
        signature = str(sample.get("signature", "") or "").strip()
        file_type = str(sample.get("file_type", "") or "").strip()
        tags = ["abuse-ch", "malwarebazaar", "malware"]
        if signature:
            tags.append(signature.lower().replace(" ", "_"))
        if file_type:
            tags.append(file_type.lower().replace(" ", "_"))

        return [ScanEvent(
            event_type="malicious_hash",
            value=parent_event.value,
            source_module=self.slug,
            root_target=ctx.root_target,
            parent_event_id=parent_event.event_id,
            confidence=90,
            visibility=100,
            risk_score=75,
            tags=tags,
            raw_payload={"sample": sample},
        )]

    def _url_events(self, payload: dict[str, Any], parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        threat = str(payload.get("threat", "") or "").strip()
        url_status = str(payload.get("url_status", "") or "").strip()
        tags = ["abuse-ch", "urlhaus", "malicious"]
        if threat:
            tags.append(threat.lower().replace(" ", "_"))
        if url_status:
            tags.append(url_status.lower().replace(" ", "_"))

        events = [ScanEvent(
            event_type="malicious_url",
            value=parent_event.value,
            source_module=self.slug,
            root_target=ctx.root_target,
            parent_event_id=parent_event.event_id,
            confidence=85,
            visibility=100,
            risk_score=75,
            tags=tags,
            raw_payload={
                "threat": threat,
                "url_status": url_status,
                "date_added": payload.get("date_added"),
            },
        )]

        host = self._extract_hostname_from_url(parent_event.value)
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
                tags=["abuse-ch", "urlhaus", "hostname"],
                raw_payload={"source_url": parent_event.value},
            ))

        return events

    def _host_events(self, payload: dict[str, Any], parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        url_count = int(payload.get("url_count", 0) or 0)
        urls_online = int(payload.get("urls_online", 0) or 0)
        threats = self._extract_host_threats(payload.get("urls") or [])

        risk_score = 75 if url_count > 0 else 0
        confidence = 85 if url_count > 0 else 60
        event_type = "malicious_internet_name" if parent_event.event_type == "domain" else "malicious_ip"
        tags = ["abuse-ch", "urlhaus", "malicious", parent_event.event_type]
        tags.extend(threats[:3])

        events: list[ScanEvent] = []
        if url_count > 0:
            events.append(ScanEvent(
                event_type=event_type,
                value=parent_event.value,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=confidence,
                visibility=100,
                risk_score=risk_score,
                tags=tags,
                raw_payload={
                    "url_count": url_count,
                    "urls_online": urls_online,
                    "threats": threats,
                },
            ))

        for url_entry in payload.get("urls") or []:
            url_value = str(url_entry.get("url", "") or "").strip()
            if not url_value:
                continue
            events.append(ScanEvent(
                event_type="linked_url_internal",
                value=url_value,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=80,
                visibility=100,
                risk_score=25,
                tags=["abuse-ch", "urlhaus", "url"],
                raw_payload={"threat": url_entry.get("threat"), "url_status": url_entry.get("url_status")},
            ))

        return events

    def _extract_hostname_from_url(self, url_value: str) -> str:
        try:
            parsed = urllib.parse.urlparse(url_value)
        except Exception:
            return ""
        return str(parsed.hostname or "").strip().lower()

    def _extract_host_threats(self, urls: list[Any]) -> list[str]:
        threats: list[str] = []
        seen: set[str] = set()
        for row in urls:
            if not isinstance(row, dict):
                continue
            threat = str(row.get("threat", "") or "").strip().lower().replace(" ", "_")
            if not threat or threat in seen:
                continue
            seen.add(threat)
            threats.append(threat)
        return threats
