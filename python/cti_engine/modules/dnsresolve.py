"""Simple DNS resolution module for the first engine slice."""

from __future__ import annotations

import socket
from typing import AsyncIterator

from ..events import ScanEvent
from ..module_base import BaseModule


class DnsResolveModule(BaseModule):
    slug = "dnsresolve"
    name = "DNS Resolve"
    watched_types = {"domain", "internet_name"}
    produced_types = {"ip", "ipv6"}

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        try:
            answers = socket.getaddrinfo(event.value, None)
        except OSError as exc:
            ctx.warning(f"DNS lookup failed for {event.value}: {exc}", self.slug)
            return

        seen_values: set[str] = set()
        for family, _, _, _, sockaddr in answers:
            value = str(sockaddr[0]).strip()
            if not value or value in seen_values:
                continue
            seen_values.add(value)
            event_type = "ipv6" if family == socket.AF_INET6 else "ip"
            ctx.info(f"Resolved {event.value} -> {value}", self.slug)
            yield ScanEvent(
                event_type=event_type,
                value=value,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=event.event_id,
                confidence=90,
                visibility=100,
                risk_score=0,
                tags=["dns", "resolution"],
                raw_payload={"source": event.value},
            )

