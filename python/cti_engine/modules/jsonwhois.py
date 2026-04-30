"""JsonWHOIS module for the first-party CTI engine."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, AsyncIterator

from ..events import ScanEvent
from ..module_base import BaseModule


class JsonWhoisModule(BaseModule):
    slug = "jsonwhois"
    name = "JsonWHOIS"
    watched_types = {"domain"}
    produced_types = {
        "raw_rir_data",
        "domain_registrar",
        "domain_whois",
        "provider_dns",
        "email",
        "email_generic",
        "affiliate_email",
        "phone_number",
        "physical_address",
        "affiliate_domain_unregistered",
    }
    requires_key = True

    DEFAULT_BASE_URL = "https://jsonwhois.com/api/v1"
    DEFAULT_GENERIC_USERS = (
        "abuse,admin,billing,compliance,devnull,dns,ftp,hostmaster,inoc,ispfeedback,"
        "ispsupport,list-request,list,maildaemon,marketing,noc,no-reply,noreply,null,"
        "peering,peering-notify,peering-request,phish,phishing,postmaster,privacy,"
        "registrar,registry,root,routing-registry,rr,sales,security,spam,support,"
        "sysadmin,tech,undisclosed-recipients,unsubscribe,usenet,uucp,webmaster,www"
    )

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        api_config = ctx.api_config_for(self.slug)
        api_key = str(api_config.get("api_key", "")).strip()
        if not api_key:
            ctx.error("JsonWHOIS module requires an API key.", self.slug)
            return

        base_url = str(api_config.get("base_url", "")).strip() or self.DEFAULT_BASE_URL
        timeout = int(ctx.request.settings.global_settings.get("http_timeout", 15) or 15)
        payload = self._fetch_payload(event.value, api_key, base_url, timeout, ctx)
        if payload is None:
            return

        for child in self._events_from_payload(payload, event, ctx):
            yield child

    def _fetch_payload(
        self,
        domain: str,
        api_key: str,
        base_url: str,
        timeout: int,
        ctx,
    ) -> dict[str, Any] | None:
        endpoint = f"{base_url.rstrip('/')}/whois?{urllib.parse.urlencode({'domain': domain})}"
        headers = {
            "Authorization": f"Token token={api_key}",
            "Accept": "application/json",
            "User-Agent": "CTI Engine",
        }
        ctx.info(f"Fetching JsonWHOIS data for {domain}.", self.slug)
        request = urllib.request.Request(endpoint, headers=headers, method="GET")

        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec - fixed provider URL
                status = int(getattr(response, "status", 200) or 200)
                content = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                ctx.info(f"JsonWHOIS has no data for {domain}.", self.slug)
                return None
            if exc.code == 500:
                try:
                    maybe = json.loads(exc.read().decode("utf-8", errors="replace"))
                except Exception:
                    maybe = None
                if maybe == {"error": "Call failed"}:
                    ctx.info(f"JsonWHOIS has no data for {domain}.", self.slug)
                    return None
            if exc.code == 429:
                ctx.error("Your request to JsonWHOIS was throttled.", self.slug)
                return None
            if exc.code in (401, 403):
                ctx.error("JsonWHOIS rejected the API key or access token.", self.slug)
                return None
            ctx.warning(f"JsonWHOIS request failed for {domain}: HTTP {exc.code}", self.slug)
            return None
        except Exception as exc:
            ctx.warning(f"JsonWHOIS request failed for {domain}: {exc}", self.slug)
            return None

        if status >= 400:
            ctx.warning(f"JsonWHOIS returned HTTP {status} for {domain}.", self.slug)
            return None

        try:
            decoded = json.loads(content)
        except json.JSONDecodeError as exc:
            ctx.error(f"JsonWHOIS returned invalid JSON: {exc}", self.slug)
            return None

        return decoded if isinstance(decoded, dict) else None

    def _events_from_payload(
        self,
        payload: dict[str, Any],
        parent_event: ScanEvent,
        ctx,
    ) -> list[ScanEvent]:
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
                tags=["whois", "jsonwhois", "raw"],
                raw_payload={"source_domain": parent_event.value},
            )
        ]

        raw_whois = str(payload.get("raw", "") or "").strip()
        if raw_whois:
            events.append(ScanEvent(
                event_type="domain_whois",
                value=raw_whois,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=88,
                visibility=100,
                risk_score=0,
                tags=["whois", "jsonwhois", "raw_whois"],
                raw_payload={"source_domain": parent_event.value},
            ))

        registrar_name = self._registrar_name(payload.get("registrar"))
        if registrar_name:
            events.append(ScanEvent(
                event_type="domain_registrar",
                value=registrar_name,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=86,
                visibility=100,
                risk_score=0,
                tags=["whois", "jsonwhois", "registrar"],
                raw_payload={"source_domain": parent_event.value},
            ))

        names = set()
        emails = set()
        phones = set()
        locations = set()
        dns_providers = set()

        for nameserver in payload.get("nameservers") or []:
            if isinstance(nameserver, dict):
                value = str(nameserver.get("name", "") or "").strip().lower().rstrip(".")
            else:
                value = str(nameserver or "").strip().lower().rstrip(".")
            if value:
                dns_providers.add(value)

        contact_blocks = []
        for key in ("registrant_contacts", "admin_contacts", "technical_contacts"):
            value = payload.get(key) or []
            if isinstance(value, list):
                contact_blocks.extend([row for row in value if isinstance(row, dict)])

        generic_users = self._generic_users(ctx)
        target_domain = parent_event.value.strip().lower()

        for contact in contact_blocks:
            email_value = str(contact.get("email", "") or "").strip().lower()
            if self._valid_email(email_value):
                emails.add(email_value)

            name = str(contact.get("name", "") or "").strip()
            if name:
                names.add(name)

            phone = self._normalize_phone(contact.get("phone"))
            if phone:
                phones.add(phone)

            location = self._build_location(contact)
            if location:
                locations.add(location)

        for provider in sorted(dns_providers):
            events.append(ScanEvent(
                event_type="provider_dns",
                value=provider,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=80,
                visibility=100,
                risk_score=0,
                tags=["whois", "jsonwhois", "dns_provider"],
                raw_payload={"source_domain": parent_event.value},
            ))

        for name in sorted(names):
            events.append(ScanEvent(
                event_type="raw_rir_data",
                value=f"Possible full name {name}",
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=65,
                visibility=100,
                risk_score=0,
                tags=["whois", "jsonwhois", "contact_name"],
                raw_payload={"source_domain": parent_event.value},
            ))

        for phone in sorted(phones):
            events.append(ScanEvent(
                event_type="phone_number",
                value=phone,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=78,
                visibility=100,
                risk_score=0,
                tags=["whois", "jsonwhois", "phone"],
                raw_payload={"source_domain": parent_event.value},
            ))

        for location in sorted(locations):
            events.append(ScanEvent(
                event_type="physical_address",
                value=location,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=76,
                visibility=100,
                risk_score=0,
                tags=["whois", "jsonwhois", "address"],
                raw_payload={"source_domain": parent_event.value},
            ))

        for email_value in sorted(emails):
            mail_domain = email_value.split("@", 1)[1]
            local_part = email_value.split("@", 1)[0]
            if mail_domain == target_domain or mail_domain.endswith("." + target_domain):
                event_type = "email_generic" if local_part in generic_users else "email"
            else:
                event_type = "affiliate_email"
            events.append(ScanEvent(
                event_type=event_type,
                value=email_value,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=82,
                visibility=100,
                risk_score=5 if event_type != "affiliate_email" else 8,
                tags=["whois", "jsonwhois", "email"],
                raw_payload={"source_domain": parent_event.value},
            ))

        if self._truthy(payload.get("available?")):
            events.append(ScanEvent(
                event_type="affiliate_domain_unregistered",
                value=parent_event.value,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=parent_event.event_id,
                confidence=84,
                visibility=100,
                risk_score=0,
                tags=["whois", "jsonwhois", "unregistered"],
                raw_payload={"source_domain": parent_event.value},
            ))

        return events

    def _registrar_name(self, value: Any) -> str:
        if isinstance(value, dict):
            return str(value.get("name", "") or "").strip()
        return str(value or "").strip()

    def _normalize_phone(self, value: Any) -> str:
        raw = str(value or "").strip()
        if not raw:
            return ""
        return re.sub(r"[ \-().]+", "", raw)

    def _build_location(self, contact: dict[str, Any]) -> str:
        parts = [
            str(contact.get("address", "") or "").strip(),
            str(contact.get("city", "") or "").strip(),
            str(contact.get("state", "") or "").strip(),
            str(contact.get("zip", "") or "").strip(),
            str(contact.get("country_code", "") or "").strip(),
        ]
        result = ", ".join([part for part in parts if part])
        return result

    def _valid_email(self, value: str) -> bool:
        if "@" not in value:
            return False
        local, domain = value.split("@", 1)
        return bool(local and domain and "." in domain)

    def _generic_users(self, ctx) -> set[str]:
        raw = str(
            ctx.request.settings.global_settings.get("generic_usernames", self.DEFAULT_GENERIC_USERS)
            or self.DEFAULT_GENERIC_USERS
        ).strip().lower()
        return {part.strip() for part in raw.split(",") if part.strip()}

    def _truthy(self, value: Any) -> bool:
        return str(value).strip().lower() not in {"0", "false", "no", "off", ""}
