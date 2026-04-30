"""PhishTank module aligned to SpiderFoot's blacklist behavior."""

from __future__ import annotations

import csv
import io
import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, AsyncIterator

from ..events import ScanEvent
from ..module_base import BaseModule


class PhishTankModule(BaseModule):
    slug = "phishtank"
    name = "PhishTank"
    watched_types = {"domain", "internet_name", "affiliate_internet_name", "co_hosted_site", "url"}
    produced_types = {
        "blacklisted_internet_name",
        "blacklisted_affiliate_internet_name",
        "blacklisted_cohost",
        "malicious_internet_name",
        "malicious_affiliate_internet_name",
        "malicious_cohost",
        "malicious_url",
        "internet_name",
    }
    requires_key = False

    CSV_URL = "https://data.phishtank.com/data/online-valid.csv"
    CHECK_URL = "https://checkurl.phishtank.com/checkurl/"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        timeout = int(ctx.request.settings.global_settings.get("http_timeout", 15) or 15)
        if event.event_type == "url":
            payload = self._fetch_url_payload(event.value, timeout, ctx)
            if payload is None:
                return
            for child in self._events_from_url_payload(payload, event, ctx):
                yield child
            return

        payload = self._fetch_domain_feed(timeout, ctx)
        if payload is None:
            return

        for child in self._events_from_domain_payload(payload, event, ctx):
            yield child

    def _fetch_domain_feed(self, timeout: int, ctx) -> list[tuple[str, str]] | None:
        request = urllib.request.Request(
            self.CSV_URL,
            headers={"Accept": "text/csv", "User-Agent": "CTI Engine"},
            method="GET",
        )
        ctx.info("Fetching PhishTank CSV feed.", self.slug)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec - fixed provider URL
                status = int(getattr(response, "status", 200) or 200)
                content = response.read().decode("utf-8", errors="replace")
        except Exception as exc:
            ctx.warning(f"PhishTank feed request failed: {exc}", self.slug)
            return None

        if status != 200:
            ctx.warning(f"PhishTank returned HTTP {status}.", self.slug)
            return None

        return self._parse_csv_feed(content)

    def _parse_csv_feed(self, content: str) -> list[tuple[str, str]]:
        results: list[tuple[str, str]] = []
        reader = csv.reader(io.StringIO(content))
        for row in reader:
            if len(row) < 2 or str(row[0]).startswith("#"):
                continue
            phish_id = str(row[0]).strip()
            url_value = str(row[1]).strip().lower()
            host = self._hostname(url_value)
            if phish_id and host:
                results.append((phish_id, host))
        return results

    def _fetch_url_payload(self, value: str, timeout: int, ctx) -> dict[str, Any] | None:
        body = urllib.parse.urlencode({"url": value, "format": "json", "app_key": ""}).encode("utf-8")
        request = urllib.request.Request(
            self.CHECK_URL,
            headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "CTI Engine"},
            data=body,
            method="POST",
        )
        ctx.info(f"Fetching PhishTank data for {value}.", self.slug)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec - fixed provider URL
                status = int(getattr(response, "status", 200) or 200)
                content = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                ctx.error("Your request to PhishTank was throttled.", self.slug)
                return None
            ctx.warning(f"PhishTank request failed for {value}: HTTP {exc.code}", self.slug)
            return None
        except Exception as exc:
            ctx.warning(f"PhishTank request failed for {value}: {exc}", self.slug)
            return None

        if status != 200:
            ctx.warning(f"PhishTank returned HTTP {status} for {value}.", self.slug)
            return None

        try:
            return json.loads(content)
        except json.JSONDecodeError as exc:
            ctx.error(f"PhishTank returned invalid JSON: {exc}", self.slug)
            return None

    def _events_from_domain_payload(
        self,
        payload: list[tuple[str, str]],
        parent_event: ScanEvent,
        ctx,
    ) -> list[ScanEvent]:
        event_types = self._host_event_pair(parent_event.event_type, ctx)
        if event_types is None:
            return []

        indicator = str(parent_event.value or "").strip().lower()
        phish_id = None
        for candidate_id, host in payload:
            if indicator in host:
                phish_id = candidate_id
                break

        if not phish_id:
            return []

        malicious_type, blacklisted_type = event_types
        detail_url = f"https://www.phishtank.com/phish_detail.php?phish_id={phish_id}"
        value = f"PhishTank [{parent_event.value}]"
        raw = {"phish_id": phish_id, "source_url": detail_url}
        return [
            ScanEvent(
                event_type=malicious_type,
                value=value,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=95,
                visibility=100,
                risk_score=90,
                tags=["phishtank", "phishing", "malicious"],
                raw_payload=raw,
            ),
            ScanEvent(
                event_type=blacklisted_type,
                value=value,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=95,
                visibility=100,
                risk_score=85,
                tags=["phishtank", "phishing", "blacklist"],
                raw_payload=raw,
            ),
        ]

    def _events_from_url_payload(
        self,
        payload: dict[str, Any],
        parent_event: ScanEvent,
        ctx,
    ) -> list[ScanEvent]:
        results = payload.get("results") if isinstance(payload.get("results"), dict) else {}
        if not results or not bool(results.get("in_database")) or not bool(results.get("valid")):
            return []

        host = self._hostname(parent_event.value)
        events = [
            ScanEvent(
                event_type="malicious_url",
                value=parent_event.value,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=99 if bool(results.get("verified")) else 85,
                visibility=100,
                risk_score=95 if bool(results.get("verified")) else 80,
                tags=["phishtank", "phishing", "malicious"],
                raw_payload={
                    "phish_id": results.get("phish_id"),
                    "detail": results.get("phish_detail_page"),
                },
            )
        ]

        if host:
            events.append(ScanEvent(
                event_type="internet_name",
                value=host,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=80,
                visibility=100,
                risk_score=10,
                tags=["phishtank", "hostname"],
                raw_payload={"source_url": parent_event.value},
            ))

        return events

    def _host_event_pair(self, event_type: str, ctx) -> tuple[str, str] | None:
        normalized = str(event_type or "").strip().lower()
        settings = ctx.module_settings_for(self.slug)

        if normalized in {"domain", "internet_name"}:
            return ("malicious_internet_name", "blacklisted_internet_name")

        if normalized == "affiliate_internet_name":
            if not self._truthy(settings.get("checkaffiliates", True)):
                return None
            return ("malicious_affiliate_internet_name", "blacklisted_affiliate_internet_name")

        if normalized == "co_hosted_site":
            if not self._truthy(settings.get("checkcohosts", True)):
                return None
            return ("malicious_cohost", "blacklisted_cohost")

        return None

    def _hostname(self, url_value: str) -> str:
        try:
            parsed = urllib.parse.urlparse(url_value)
        except Exception:
            return ""
        return str(parsed.hostname or "").strip().lower()

    def _truthy(self, value: Any) -> bool:
        return str(value).strip().lower() not in {"0", "false", "no", "off", ""}
