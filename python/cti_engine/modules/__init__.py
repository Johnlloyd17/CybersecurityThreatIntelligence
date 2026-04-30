"""Built-in CTI engine modules."""

from __future__ import annotations

from ..registry import ModuleRegistry
from .apivoid import ApiVoidModule
from .abusech import AbuseChModule
from .abuseipdb import AbuseIpDbModule
from .alienvault import AlienVaultModule
from .bgpview import BgpViewModule
from .certspotter import CertSpotterModule
from .censys import CensysModule
from .crtsh import CrtShModule
from .dnsdumpster import DnsDumpsterModule
from .dnsresolve import DnsResolveModule
from .emailrep import EmailRepModule
from .greynoise import GreyNoiseModule
from .haveibeenpwned import HaveIBeenPwnedModule
from .hunter import HunterModule
from .ipinfo import IpInfoModule
from .ipqualityscore import IpQualityScoreModule
from .ipregistry import IpRegistryModule
from .jsonwhois import JsonWhoisModule
from .leakix import LeakIxModule
from .no_key_reputation import (
    AdBlockCheckModule,
    Base64DecoderModule,
    BlocklistDeModule,
    BotvrijModule,
    CinsScoreModule,
    CoinBlockerModule,
    CyberCrimeTrackerModule,
    DroneBlModule,
    EmergingThreatsModule,
    GreenSnowModule,
    MultiProxyModule,
    SpamCopModule,
    SpamHausZenModule,
    StevenBlackHostsModule,
    SurblModule,
    ThreatMinerModule,
    TorExitNodesModule,
    UceProtectModule,
    VxVaultModule,
    ZoneHModule,
)
from .openphish import OpenPhishModule
from .passivedns import PassiveDnsModule
from .phishtank import PhishTankModule
from .securitytrails import SecurityTrailsModule
from .shodan import ShodanModule
from .threatfox import ThreatFoxModule
from .urlscan import UrlscanModule
from .virustotal import VirusTotalModule
from .viewdns import ViewDnsModule
from .wave1_osint import (
    ArchiveOrgModule,
    CommonCrawlModule,
    CrobatModule,
    HackerTargetModule,
    IscSansModule,
    MaltiverseModule,
    MnemonicPdnsModule,
    PhishStatsModule,
    RobtexModule,
    ThreatCrowdModule,
)
from .wave2_osint import (
    AhmiaModule,
    DnsBruteforceModule,
    DnsGrepModule,
    DnsRawModule,
    DuckDuckGoModule,
    GrepAppModule,
    SearchcodeModule,
    SslAnalyzerModule,
    TldSearcherModule,
    VoipBlModule,
)
from .wave3_sources import (
    CrxCavatorModule,
    FlickrModule,
    GitHubModule,
    OnionSearchEngineModule,
    PgpKeyServersModule,
    TorchModule,
    WikipediaEditsModule,
    WikileaksModule,
)
from .wave4_discovery import (
    AzureBlobFinderModule,
    DnsLookasideModule,
    DnsTwistModule,
    DnsZoneTransferModule,
    DoSpaceFinderModule,
    GcsFinderModule,
    OpenNicModule,
    OpenPdnsModule,
    S3FinderModule,
    WebSpiderModule,
)
from .wave5_extractors import (
    AccountFinderModule,
    BinaryStringExtractorModule,
    CmSeekModule,
    CompanyNameExtractorModule,
    CountryNameExtractorModule,
    CrossReferencerModule,
    FileMetadataExtractorModule,
    HumanNameExtractorModule,
    InterestingFileFinderModule,
    JunkFileFinderModule,
)
from .wave6_reputation import (
    AlienVaultIpRepModule,
    CleanTalkModule,
    CustomThreatFeedModule,
    FortiGuardModule,
    MalwarePatrolModule,
    RetireJsModule,
    ScyllaModule,
    SnallygasterModule,
    SorbsModule,
    TalosIntelligenceModule,
)
from .wave7_tools import (
    NbtscanModule,
    NmapModule,
    NucleiModule,
    OneSixtyOneModule,
    PortScannerTcpModule,
    TestSslModule,
    TruffleHogModule,
    Wafw00fModule,
    WappalyzerModule,
    WhatWebModule,
)
from .whoisology import WhoisologyModule
from .whoxy import WhoxyModule


def register_builtin_modules(registry: ModuleRegistry) -> ModuleRegistry:
    registry.register(AdBlockCheckModule)
    registry.register(AhmiaModule)
    registry.register(AccountFinderModule)
    registry.register(ApiVoidModule)
    registry.register(ArchiveOrgModule)
    registry.register(AbuseChModule)
    registry.register(AbuseIpDbModule)
    registry.register(AlienVaultModule)
    registry.register(AlienVaultIpRepModule)
    registry.register(AzureBlobFinderModule)
    registry.register(CommonCrawlModule)
    registry.register(CompanyNameExtractorModule)
    registry.register(CountryNameExtractorModule)
    registry.register(Base64DecoderModule)
    registry.register(BgpViewModule)
    registry.register(BlocklistDeModule)
    registry.register(BotvrijModule)
    registry.register(CertSpotterModule)
    registry.register(CensysModule)
    registry.register(CinsScoreModule)
    registry.register(CleanTalkModule)
    registry.register(CoinBlockerModule)
    registry.register(CrobatModule)
    registry.register(CrossReferencerModule)
    registry.register(CrtShModule)
    registry.register(CustomThreatFeedModule)
    registry.register(CyberCrimeTrackerModule)
    registry.register(DnsBruteforceModule)
    registry.register(DnsLookasideModule)
    registry.register(DnsGrepModule)
    registry.register(DnsDumpsterModule)
    registry.register(DnsRawModule)
    registry.register(DnsResolveModule)
    registry.register(DnsTwistModule)
    registry.register(DnsZoneTransferModule)
    registry.register(DoSpaceFinderModule)
    registry.register(DroneBlModule)
    registry.register(DuckDuckGoModule)
    registry.register(EmailRepModule)
    registry.register(EmergingThreatsModule)
    registry.register(FileMetadataExtractorModule)
    registry.register(FlickrModule)
    registry.register(FortiGuardModule)
    registry.register(GcsFinderModule)
    registry.register(GrepAppModule)
    registry.register(GitHubModule)
    registry.register(GreyNoiseModule)
    registry.register(GreenSnowModule)
    registry.register(HackerTargetModule)
    registry.register(HaveIBeenPwnedModule)
    registry.register(HumanNameExtractorModule)
    registry.register(HunterModule)
    registry.register(IpInfoModule)
    registry.register(IpQualityScoreModule)
    registry.register(IpRegistryModule)
    registry.register(IscSansModule)
    registry.register(JsonWhoisModule)
    registry.register(JunkFileFinderModule)
    registry.register(LeakIxModule)
    registry.register(MaltiverseModule)
    registry.register(MalwarePatrolModule)
    registry.register(MnemonicPdnsModule)
    registry.register(MultiProxyModule)
    registry.register(NbtscanModule)
    registry.register(NmapModule)
    registry.register(NucleiModule)
    registry.register(OnionSearchEngineModule)
    registry.register(OneSixtyOneModule)
    registry.register(OpenNicModule)
    registry.register(OpenPdnsModule)
    registry.register(OpenPhishModule)
    registry.register(PassiveDnsModule)
    registry.register(PgpKeyServersModule)
    registry.register(PhishStatsModule)
    registry.register(PhishTankModule)
    registry.register(PortScannerTcpModule)
    registry.register(RetireJsModule)
    registry.register(RobtexModule)
    registry.register(ScyllaModule)
    registry.register(SearchcodeModule)
    registry.register(SecurityTrailsModule)
    registry.register(S3FinderModule)
    registry.register(ShodanModule)
    registry.register(SpamCopModule)
    registry.register(SpamHausZenModule)
    registry.register(SnallygasterModule)
    registry.register(SorbsModule)
    registry.register(StevenBlackHostsModule)
    registry.register(SurblModule)
    registry.register(SslAnalyzerModule)
    registry.register(BinaryStringExtractorModule)
    registry.register(CmSeekModule)
    registry.register(CrxCavatorModule)
    registry.register(InterestingFileFinderModule)
    registry.register(TldSearcherModule)
    registry.register(TalosIntelligenceModule)
    registry.register(ThreatCrowdModule)
    registry.register(ThreatFoxModule)
    registry.register(ThreatMinerModule)
    registry.register(TorchModule)
    registry.register(TorExitNodesModule)
    registry.register(TestSslModule)
    registry.register(TruffleHogModule)
    registry.register(UceProtectModule)
    registry.register(UrlscanModule)
    registry.register(VirusTotalModule)
    registry.register(VoipBlModule)
    registry.register(VxVaultModule)
    registry.register(ViewDnsModule)
    registry.register(Wafw00fModule)
    registry.register(WappalyzerModule)
    registry.register(WebSpiderModule)
    registry.register(WhatWebModule)
    registry.register(WikipediaEditsModule)
    registry.register(WikileaksModule)
    registry.register(WhoisologyModule)
    registry.register(WhoxyModule)
    registry.register(ZoneHModule)
    return registry


__all__ = [
    "AdBlockCheckModule",
    "AhmiaModule",
    "AccountFinderModule",
    "ApiVoidModule",
    "ArchiveOrgModule",
    "AbuseChModule",
    "AbuseIpDbModule",
    "AlienVaultModule",
    "AlienVaultIpRepModule",
    "AzureBlobFinderModule",
    "CommonCrawlModule",
    "CompanyNameExtractorModule",
    "CountryNameExtractorModule",
    "Base64DecoderModule",
    "BgpViewModule",
    "BlocklistDeModule",
    "BotvrijModule",
    "CertSpotterModule",
    "CensysModule",
    "CinsScoreModule",
    "CleanTalkModule",
    "CoinBlockerModule",
    "CrobatModule",
    "CrossReferencerModule",
    "CrtShModule",
    "CustomThreatFeedModule",
    "CyberCrimeTrackerModule",
    "BinaryStringExtractorModule",
    "CmSeekModule",
    "DnsBruteforceModule",
    "DnsLookasideModule",
    "DnsGrepModule",
    "DnsDumpsterModule",
    "DnsRawModule",
    "DnsResolveModule",
    "DnsTwistModule",
    "DnsZoneTransferModule",
    "DoSpaceFinderModule",
    "DroneBlModule",
    "DuckDuckGoModule",
    "EmailRepModule",
    "EmergingThreatsModule",
    "FileMetadataExtractorModule",
    "FlickrModule",
    "FortiGuardModule",
    "GcsFinderModule",
    "GrepAppModule",
    "GitHubModule",
    "GreyNoiseModule",
    "GreenSnowModule",
    "HackerTargetModule",
    "HaveIBeenPwnedModule",
    "HumanNameExtractorModule",
    "HunterModule",
    "IpInfoModule",
    "IpQualityScoreModule",
    "IpRegistryModule",
    "IscSansModule",
    "JsonWhoisModule",
    "JunkFileFinderModule",
    "LeakIxModule",
    "MaltiverseModule",
    "MalwarePatrolModule",
    "MnemonicPdnsModule",
    "MultiProxyModule",
    "NbtscanModule",
    "NmapModule",
    "NucleiModule",
    "OnionSearchEngineModule",
    "OneSixtyOneModule",
    "OpenNicModule",
    "OpenPdnsModule",
    "OpenPhishModule",
    "PassiveDnsModule",
    "PgpKeyServersModule",
    "PhishStatsModule",
    "PhishTankModule",
    "PortScannerTcpModule",
    "RetireJsModule",
    "RobtexModule",
    "ScyllaModule",
    "SearchcodeModule",
    "SecurityTrailsModule",
    "S3FinderModule",
    "ShodanModule",
    "SpamCopModule",
    "SpamHausZenModule",
    "SnallygasterModule",
    "SorbsModule",
    "StevenBlackHostsModule",
    "SurblModule",
    "SslAnalyzerModule",
    "CrxCavatorModule",
    "InterestingFileFinderModule",
    "TldSearcherModule",
    "TalosIntelligenceModule",
    "ThreatCrowdModule",
    "ThreatFoxModule",
    "ThreatMinerModule",
    "TorchModule",
    "TorExitNodesModule",
    "TestSslModule",
    "TruffleHogModule",
    "UceProtectModule",
    "UrlscanModule",
    "VirusTotalModule",
    "VoipBlModule",
    "VxVaultModule",
    "ViewDnsModule",
    "Wafw00fModule",
    "WappalyzerModule",
    "WebSpiderModule",
    "WhatWebModule",
    "WikipediaEditsModule",
    "WikileaksModule",
    "WhoisologyModule",
    "WhoxyModule",
    "ZoneHModule",
    "register_builtin_modules",
]
