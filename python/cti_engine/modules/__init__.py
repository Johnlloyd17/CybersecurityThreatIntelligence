"""Built-in CTI engine modules."""

from __future__ import annotations

from ..registry import ModuleRegistry
from .apivoid import ApiVoidModule
from .abusech import AbuseChModule
from .abuseipdb import AbuseIpDbModule
from .alienvault import AlienVaultModule
from .certspotter import CertSpotterModule
from .crtsh import CrtShModule
from .dnsresolve import DnsResolveModule
from .jsonwhois import JsonWhoisModule
from .shodan import ShodanModule
from .urlscan import UrlscanModule
from .virustotal import VirusTotalModule
from .whoisology import WhoisologyModule
from .whoxy import WhoxyModule


def register_builtin_modules(registry: ModuleRegistry) -> ModuleRegistry:
    registry.register(ApiVoidModule)
    registry.register(AbuseChModule)
    registry.register(AbuseIpDbModule)
    registry.register(AlienVaultModule)
    registry.register(CertSpotterModule)
    registry.register(CrtShModule)
    registry.register(DnsResolveModule)
    registry.register(JsonWhoisModule)
    registry.register(ShodanModule)
    registry.register(UrlscanModule)
    registry.register(VirusTotalModule)
    registry.register(WhoisologyModule)
    registry.register(WhoxyModule)
    return registry


__all__ = [
    "ApiVoidModule",
    "AbuseChModule",
    "AbuseIpDbModule",
    "AlienVaultModule",
    "CertSpotterModule",
    "CrtShModule",
    "DnsResolveModule",
    "JsonWhoisModule",
    "ShodanModule",
    "UrlscanModule",
    "VirusTotalModule",
    "WhoisologyModule",
    "WhoxyModule",
    "register_builtin_modules",
]
