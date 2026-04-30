"""Wave 5 no-key extractors, correlators, and tool wrappers for the CTI engine."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import io
import json
from pathlib import Path
import random
import re
from shutil import which
import subprocess
import urllib.parse
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from typing import Any, AsyncIterator

from ..events import ScanEvent
from ..module_base import BaseModule
from .no_key_reputation import (
    USER_AGENT,
    _cti_slug,
    _fetch_text,
    _hostname,
    _host_resolves,
    _http_timeout,
    _make_event,
    _matches_root_target,
    _module_bool,
    _module_int,
    _module_setting,
)
from .wave4_discovery import _fetch_http


HTML_LINK_RX = re.compile(r"""(?:href|src)=["']([^"'#]+)""", re.I)
PRINTABLE_BLOCK_RX = re.compile(rb"[\x20-\x7e]{5,}")
HTML_TAG_RX = re.compile(r"<[^>]+>")
NAME_RX = re.compile(r"\b([A-Z][a-z]+)\s+.?.?\s?([A-Z][A-Za-z'\-]+)\b")
WIKI_LINK_RX = re.compile(r"<link>(.*?)</link>", re.I)
COMPANY_PREFIX = r"(?=[,;:\'\">\(= ]|^)\s?([A-Z0-9\(\)][A-Za-z0-9\-&,\.][^ \"\';:><]*)?\s?([A-Z0-9\(\)][A-Za-z0-9\-&,\.]?[^ \"\';:><]*|[Aa]nd)?\s?([A-Z0-9\(\)][A-Za-z0-9\-&,\.]?[^ \"\';:><]*)?\s+"
COMPANY_SUFFIX = r"(?=[ \.,:<\)\'\"]|[$\n\r])"
COMPANY_MATCH_RE = [
    "LLC", r"L\.L\.C\.?", "AG", r"A\.G\.?", "GmbH", r"Pty\.?\s+Ltd\.?",
    r"Ltd\.?", r"Pte\.?", r"Inc\.?", r"INC\.?", "Incorporated", "Foundation",
    r"Corp\.?", "Corporation", "SA", r"S\.A\.?", "SIA", "BV", r"B\.V\.?",
    "NV", r"N\.V\.?", "PLC", "Limited", r"Pvt\.?\s+Ltd\.?", "SARL",
]
COMPANY_MATCHES = [
    "LLC", "L.L.C", "AG", "A.G", "GmbH", "Pty", "Ltd", "Pte", "Inc", "INC",
    "Foundation", "Corp", "SA", "S.A", "SIA", "BV", "B.V", "NV", "N.V",
    "PLC", "Limited", "Pvt.", "SARL",
]
COMPANY_FILTERS = ["Copyright", r"\d{4}"]

COMMON_FIRST_NAMES = {
    "aaron", "adam", "adrian", "alex", "alice", "andrew", "anna", "anthony",
    "ben", "bob", "charles", "daniel", "david", "emily", "eric", "george",
    "jane", "jason", "john", "joseph", "julia", "kevin", "maria", "mark",
    "mary", "michael", "paul", "peter", "robert", "sarah", "steve", "thomas",
    "victor", "william",
}

COMMON_WORDS = {
    "about", "account", "admin", "blog", "company", "contact", "dashboard",
    "default", "email", "hello", "home", "login", "news", "portal", "privacy",
    "profile", "sample", "search", "service", "support", "system", "target",
    "team", "user", "website",
}

COUNTRY_BY_TLD = {
    "au": "Australia",
    "br": "Brazil",
    "ca": "Canada",
    "cn": "China",
    "de": "Germany",
    "es": "Spain",
    "fr": "France",
    "hk": "Hong Kong",
    "id": "Indonesia",
    "ie": "Ireland",
    "in": "India",
    "it": "Italy",
    "jp": "Japan",
    "kr": "South Korea",
    "mx": "Mexico",
    "my": "Malaysia",
    "nl": "Netherlands",
    "nz": "New Zealand",
    "ph": "Philippines",
    "ru": "Russia",
    "sg": "Singapore",
    "th": "Thailand",
    "tw": "Taiwan",
    "uk": "United Kingdom",
    "us": "United States",
    "vn": "Vietnam",
    "za": "South Africa",
}

COUNTRY_CODE_MAP = {
    "AU": "Australia",
    "BR": "Brazil",
    "CA": "Canada",
    "CN": "China",
    "DE": "Germany",
    "ES": "Spain",
    "FR": "France",
    "GB": "United Kingdom",
    "HK": "Hong Kong",
    "ID": "Indonesia",
    "IE": "Ireland",
    "IN": "India",
    "IT": "Italy",
    "JP": "Japan",
    "KR": "South Korea",
    "MX": "Mexico",
    "MY": "Malaysia",
    "NL": "Netherlands",
    "NZ": "New Zealand",
    "PH": "Philippines",
    "RU": "Russia",
    "SG": "Singapore",
    "TH": "Thailand",
    "TW": "Taiwan",
    "US": "United States",
    "VN": "Vietnam",
    "ZA": "South Africa",
}

COUNTRY_NAMES = sorted(set(COUNTRY_BY_TLD.values()) | set(COUNTRY_CODE_MAP.values()), key=len, reverse=True)
PHONE_PREFIX_COUNTRIES = [
    ("+63", "Philippines"),
    ("+65", "Singapore"),
    ("+66", "Thailand"),
    ("+81", "Japan"),
    ("+82", "South Korea"),
    ("+84", "Vietnam"),
    ("+91", "India"),
    ("+44", "United Kingdom"),
    ("+49", "Germany"),
    ("+33", "France"),
    ("+39", "Italy"),
    ("+34", "Spain"),
    ("+61", "Australia"),
    ("+64", "New Zealand"),
    ("+1", "United States"),
]

ACCOUNT_FEED_URL = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
ACCOUNT_CACHE: list[dict[str, Any]] | None = None

try:  # pragma: no cover - optional dependency.
    import exifread  # type: ignore
except Exception:  # pragma: no cover - intentionally optional.
    exifread = None


def _normalize_indicator(value: str) -> str:
    return str(_hostname(value) or value or "").strip().lower().rstrip(".")


def _domain_keyword(value: str) -> str:
    indicator = _normalize_indicator(value)
    if not indicator or "." not in indicator:
        return indicator
    return indicator.split(".", 1)[0].strip().lower()


def _strip_html(text: str) -> str:
    return HTML_TAG_RX.sub(" ", str(text or ""))


def _seed_urls_for_event(event: ScanEvent) -> list[str]:
    if event.event_type in {"url", "linked_url_internal", "linked_url_external", "darknet_mention_url"}:
        return [event.value]
    if event.event_type in {"domain", "internet_name"}:
        host = _normalize_indicator(event.value)
        if not host:
            return []
        return [f"https://{host}", f"http://{host}"]
    return []


def _first_page_content(event: ScanEvent, ctx, slug: str) -> tuple[str, str, dict[str, str]] | None:
    timeout = _http_timeout(ctx)
    for url in _seed_urls_for_event(event):
        status, body, final_url, headers = _fetch_http(
            url,
            timeout,
            ctx,
            slug,
            accept="text/html, text/plain, */*",
            max_bytes=1_000_000,
        )
        if status and body:
            return body, final_url, headers
    return None


def _fetch_binary(url: str, timeout: int, ctx, slug: str, max_bytes: int) -> bytes | None:
    request = urllib.request.Request(
        url,
        headers={"Accept": "*/*", "User-Agent": USER_AGENT},
        method="GET",
    )
    ctx.info(f"Fetching binary content from {url}.", slug)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec - seeded CTI target URL
            content = response.read(max_bytes + 1)
            if len(content) > max_bytes:
                content = content[:max_bytes]
            return content
    except Exception as exc:
        ctx.warning(f"{slug} binary fetch failed: {exc}", slug)
        return None


def _head_status(url: str, timeout: int, ctx, slug: str) -> tuple[int, str]:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT},
        method="HEAD",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec - seeded CTI target URL
            status = int(getattr(response, "status", 200) or 200)
            real_url = str(getattr(response, "geturl", lambda: url)() or url)
            return status, real_url
    except urllib.error.HTTPError as exc:
        return int(exc.code or 0), str(exc.geturl() or url)
    except Exception as exc:
        ctx.debug(f"{slug} HEAD request failed for {url}: {exc}", slug)
        return 0, url


def _extract_links(content: str, base_url: str) -> list[str]:
    links: list[str] = []
    seen: set[str] = set()
    for match in HTML_LINK_RX.findall(str(content or "")):
        absolute = urllib.parse.urljoin(base_url, str(match or "").strip())
        if not absolute or absolute in seen:
            continue
        seen.add(absolute)
        links.append(absolute)
    return links


def _interesting_file_exts(ctx, slug: str) -> list[str]:
    value = _module_setting(ctx, slug, _cti_slug(slug), ("fileexts", "file_extensions"), ["doc", "docx", "ppt", "pptx", "pdf", "xls", "xlsx", "zip"])
    if isinstance(value, str):
        items = [item.strip().lstrip(".").lower() for item in value.split(",")]
    else:
        items = [str(item or "").strip().lstrip(".").lower() for item in value]
    return [item for item in items if item]


def _candidate_usernames(event: ScanEvent, ctx) -> list[str]:
    event_value = str(event.value or "").strip()
    if not event_value:
        return []
    if event.event_type == "username":
        return [event_value.lower()]
    if event.event_type in {"email", "email_generic"} and _module_bool(ctx, "account-finder", "account-finder", ("extract_emails", "userfromemail"), True):
        return [event_value.split("@")[0].lower()]
    if event.event_type in {"domain", "domain_name", "internet_name"}:
        keyword = _domain_keyword(event_value)
        return [keyword] if keyword else []
    if event.event_type == "human_name":
        lowered = event_value.lower().strip()
        return [lowered.replace(" ", ""), lowered.replace(" ", ".")]
    return []


def _site_account_match(url: str, username: str, site: dict[str, Any], body: str, status: int) -> bool:
    expected_code = site.get("e_code")
    missing_code = site.get("m_code")
    if expected_code and status != int(expected_code):
        return False
    if missing_code and status == int(missing_code):
        return False
    expected_string = str(site.get("e_string", "") or "")
    missing_string = str(site.get("m_string", "") or "")
    body_text = str(body or "")
    if expected_string and expected_string not in body_text:
        return False
    if missing_string and missing_string in body_text:
        return False
    if username.lower() not in body_text.lower():
        return False
    if "." in username:
        firstname = username.split(".", 1)[0]
        if firstname + "<" in body_text or firstname + '"' in body_text:
            return False
    return True


def _load_account_sites(ctx, slug: str) -> list[dict[str, Any]]:
    global ACCOUNT_CACHE
    if ACCOUNT_CACHE is not None:
        return ACCOUNT_CACHE

    content = _fetch_text(ACCOUNT_FEED_URL, _http_timeout(ctx), ctx, slug, accept="application/json, text/plain, */*")
    if not content:
        return []
    try:
        parsed = json.loads(content)
        ACCOUNT_CACHE = [site for site in parsed.get("sites", []) if site.get("valid", True) is not False]
    except Exception as exc:
        ctx.warning(f"{slug} failed to parse account feed: {exc}", slug)
        return []
    return ACCOUNT_CACHE or []


def _fetch_account_site(username: str, site: dict[str, Any], timeout: int) -> tuple[dict[str, Any], int, str]:
    check_url = str(site.get("uri_check", "") or "").strip()
    if not check_url:
        return site, 0, ""
    url = check_url.format(account=username)
    post_body = site.get("post_body")
    data = None if not post_body else str(post_body).encode("utf-8")
    request = urllib.request.Request(url, data=data, headers={"User-Agent": USER_AGENT}, method="POST" if data else "GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec - provider URL comes from WhatsMyName feed
            status = int(getattr(response, "status", 200) or 200)
            body = response.read().decode("utf-8", errors="replace")
            return site, status, body
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return site, int(exc.code or 0), body
    except Exception:
        return site, 0, ""


def _link_host(url: str) -> str:
    return _normalize_indicator(url)


def _is_internal_url(url: str, root_target: str) -> bool:
    host = _link_host(url)
    return bool(host and _matches_root_target(host, root_target))


def _country_from_domain(value: str) -> str | None:
    host = _normalize_indicator(value)
    if not host:
        return None
    for part in reversed(host.split(".")):
        if part in COUNTRY_BY_TLD:
            return COUNTRY_BY_TLD[part]
    return None


def _country_from_phone(value: str) -> str | None:
    phone = str(value or "").strip().replace(" ", "")
    for prefix, country in PHONE_PREFIX_COUNTRIES:
        if phone.startswith(prefix):
            return country
    return None


def _countries_from_text(text: str) -> list[str]:
    haystack = str(text or "")
    matches: list[str] = []
    lowered = haystack.lower()
    for country in COUNTRY_NAMES:
        if country.lower() not in lowered:
            continue
        if re.search(rf"(?<![A-Za-z]){re.escape(country)}(?![A-Za-z])", haystack, re.I):
            matches.append(country)
    for match in re.findall(r"country:\s*([A-Za-z]{2,40})", haystack, re.I):
        candidate = str(match or "").strip()
        upper = candidate.upper()
        if upper in COUNTRY_CODE_MAP:
            matches.append(COUNTRY_CODE_MAP[upper])
        elif candidate.title() in COUNTRY_NAMES:
            matches.append(candidate.title())
    unique: list[str] = []
    seen: set[str] = set()
    for item in matches:
        lowered_item = item.lower()
        if lowered_item in seen:
            continue
        seen.add(lowered_item)
        unique.append(item)
    return unique


def _pdf_metadata(content: bytes) -> tuple[str | None, list[str]]:
    text = content.decode("latin-1", errors="ignore")
    raw_parts: list[str] = []
    software: list[str] = []
    for key in ("Producer", "Creator", "Author", "Title"):
        pattern = re.compile(rf"/{key}\s*\((.*?)\)", re.I | re.S)
        match = pattern.search(text)
        if not match:
            continue
        value = re.sub(r"\s+", " ", match.group(1)).strip()
        if not value:
            continue
        raw_parts.append(f"{key}: {value}")
        if key in {"Producer", "Creator"}:
            software.append(value)
    if not raw_parts:
        return None, []
    return ", ".join(raw_parts), software


def _office_core_properties(content: bytes) -> tuple[str | None, list[str]]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(content))
    except Exception:
        return None, []
    try:
        with archive.open("docProps/core.xml") as handle:
            tree = ET.fromstring(handle.read())
    except Exception:
        archive.close()
        return None, []

    ns = {
        "dc": "http://purl.org/dc/elements/1.1/",
        "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
    }
    values: list[str] = []
    software: list[str] = []
    for xpath, label in (
        ("dc:creator", "Author"),
        ("dc:title", "Title"),
        ("cp:keywords", "Keywords"),
        ("dc:description", "Comments"),
    ):
        node = tree.find(xpath, ns)
        if node is None or not (node.text or "").strip():
            continue
        text = str(node.text or "").strip()
        values.append(f"{label}: {text}")
        if label == "Author":
            software.append(text)
    archive.close()
    if not values:
        return None, []
    return ", ".join(values), software


def _image_metadata(content: bytes) -> tuple[str | None, list[str]]:
    if exifread is None:
        return None, []
    try:
        tags = exifread.process_file(io.BytesIO(content), details=False)
    except Exception:
        return None, []
    if not tags:
        return None, []

    values: list[str] = []
    software: list[str] = []
    for key in ("Image Software", "Image Artist", "Image ImageDescription"):
        if key not in tags:
            continue
        text = str(tags[key]).strip()
        if not text:
            continue
        values.append(f"{key}: {text}")
        if key == "Image Software":
            software.append(text)
    if not values:
        return str(tags), software
    return ", ".join(values), software


def _normalize_ascii(text: str) -> str:
    return "".join(ch if ord(ch) < 128 else " " for ch in str(text or ""))


def _cmseek_paths(base: str) -> tuple[str, str]:
    raw = str(base or "").strip().replace("\\", "/")
    if raw.endswith("cmseek.py"):
        return raw, raw.rsplit("cmseek.py", 1)[0] + "Result"
    if raw.endswith("/"):
        return raw + "cmseek.py", raw + "Result"
    return raw + "/cmseek.py", raw + "/Result"


def _read_cmseek_result(result_root: str, target: str) -> dict[str, Any] | None:
    candidate = Path(result_root) / target / "cms.json"
    if not candidate.is_file():
        return None
    try:
        return json.loads(candidate.read_text(encoding="utf-8"))
    except Exception:
        return None


class AccountFinderModule(BaseModule):
    slug = "account-finder"
    name = "Account Finder"
    watched_types = {"username", "email", "email_generic", "domain", "domain_name", "internet_name", "human_name"}
    produced_types = {"username", "account_external_owned", "similar_account_external"}
    requires_key = False

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        usernames = self._candidate_users(event, ctx)
        if not usernames:
            return
        if event.event_type != "username":
            for username in usernames:
                yield _make_event(
                    event_type="username",
                    value=username,
                    slug=self.slug,
                    parent_event=event,
                    ctx=ctx,
                    risk_score=5,
                    confidence=70,
                    tags=["accounts", "username"],
                    raw_payload={"spiderfoot_parity": True},
                )
            return

        sites = _load_account_sites(ctx, self.slug)
        if not sites:
            return
        timeout = _http_timeout(ctx)
        for username in usernames:
            for child in self._events_for_username(username, event, ctx, sites, timeout):
                yield child

    def _candidate_users(self, event: ScanEvent, ctx) -> list[str]:
        users: list[str] = []
        generic = {
            item.strip().lower()
            for item in str(
                ctx.request.settings.global_settings.get("generic_usernames")
                or ctx.request.settings.global_settings.get("_genericusers")
                or ""
            ).split(",")
            if item.strip()
        }
        skip_first = _module_bool(ctx, self.slug, _cti_slug(self.slug), ("skip_first_names", "ignorenamedict"), True)
        skip_words = _module_bool(ctx, self.slug, _cti_slug(self.slug), ("skip_dictionary", "ignoreworddict"), True)
        min_size = _module_int(ctx, self.slug, _cti_slug(self.slug), ("minimum_username_length", "usernamesize"), 4)

        for candidate in _candidate_usernames(event, ctx):
            normalized = str(candidate or "").strip().lower()
            if not normalized:
                continue
            if normalized in generic:
                continue
            if skip_first and normalized in COMMON_FIRST_NAMES:
                continue
            if skip_words and normalized in COMMON_WORDS:
                continue
            if len(normalized) < min_size:
                continue
            users.append(normalized)
        return sorted(set(users))

    def _events_for_username(
        self,
        username: str,
        parent_event: ScanEvent,
        ctx,
        sites: list[dict[str, Any]],
        timeout: int,
    ) -> list[ScanEvent]:
        require_mention = _module_bool(ctx, self.slug, _cti_slug(self.slug), ("require_username_mention", "musthavename"), True)
        max_threads = max(1, _module_int(ctx, self.slug, _cti_slug(self.slug), "_maxthreads", 12))
        matches = self._check_sites(username, sites, timeout, max_threads, require_mention)
        events: list[ScanEvent] = []
        for value in matches:
            events.append(_make_event(
                event_type="account_external_owned",
                value=value,
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=20,
                confidence=75,
                tags=["accounts", "owned-account"],
                raw_payload={"username": username, "spiderfoot_parity": True},
            ))

        if not _module_bool(ctx, self.slug, _cti_slug(self.slug), ("check_permutations", "permutate"), False):
            return events

        for permutation in self._generate_permutations(username):
            for value in self._check_sites(permutation, sites, timeout, max_threads, require_mention):
                events.append(_make_event(
                    event_type="similar_account_external",
                    value=value,
                    slug=self.slug,
                    parent_event=parent_event,
                    ctx=ctx,
                    risk_score=15,
                    confidence=65,
                    tags=["accounts", "permutation-account"],
                    raw_payload={"username": permutation, "spiderfoot_parity": True},
                ))
        return events

    def _check_sites(self, username: str, sites: list[dict[str, Any]], timeout: int, max_threads: int, require_mention: bool) -> list[str]:
        matches: list[str] = []
        with ThreadPoolExecutor(max_workers=min(max_threads, max(1, len(sites)))) as pool:
            futures = [pool.submit(_fetch_account_site, username, site, timeout) for site in sites]
            for future in as_completed(futures):
                site, status, body = future.result()
                if not body:
                    continue
                if require_mention and username.lower() not in body.lower():
                    continue
                if not _site_account_match("", username, site, body, status):
                    continue
                pretty = str(site.get("uri_pretty") or site.get("uri_check") or "").format(account=username)
                matches.append(f"{site.get('name', 'Unknown')} (Category: {site.get('cat', 'Unknown')})\n<SFURL>{pretty}</SFURL>")
        return sorted(set(matches))

    def _generate_permutations(self, username: str) -> list[str]:
        prefixsuffix = ["_", "-"]
        replacements = {
            "a": ["4", "s"], "b": ["v", "n"], "c": ["x", "v"], "d": ["s", "f"],
            "e": ["w", "r"], "f": ["d", "g"], "g": ["f", "h"], "h": ["g", "j", "n"],
            "i": ["o", "u", "1"], "j": ["k", "h", "i"], "k": ["l", "j"],
            "l": ["i", "1", "k"], "m": ["n"], "n": ["m"], "o": ["p", "i", "0"],
            "p": ["o", "q"], "r": ["t", "e"], "s": ["a", "d", "5"], "t": ["7", "y", "z", "r"],
            "u": ["v", "i", "y", "z"], "v": ["u", "c", "b"], "w": ["v", "vv", "q", "e"],
            "x": ["z", "y", "c"], "y": ["z", "x"], "z": ["y", "x"], "0": ["o"], "1": ["l"],
            "2": ["5"], "3": ["e"], "4": ["a"], "5": ["s"], "6": ["b"], "7": ["t"], "8": ["b"], "9": [],
        }
        pairs = {"oo": ["00"], "ll": ["l1l", "111", "11"], "11": ["ll", "lll", "l1l", "1l1"]}
        permutations: set[str] = set()
        for index, char in enumerate(username):
            for replacement in replacements.get(char, []):
                permutations.add(username[:index] + replacement + username[index + 1 :])
            permutations.add(username[:index] + char + char + username[index + 1 :])
        for pair, replacement_values in pairs.items():
            if pair in username:
                for replacement in replacement_values:
                    permutations.add(username.replace(pair, replacement))
        for item in prefixsuffix:
            permutations.add(username + item)
            permutations.add(item + username)
        permutations.discard(username)
        return sorted(permutations)


class BinaryStringExtractorModule(BaseModule):
    slug = "binary-string-extractor"
    name = "Binary String Extractor"
    watched_types = {"url", "linked_url_internal", "interesting_file"}
    produced_types = {"raw_file_meta_data"}
    requires_key = False

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        if not self._looks_interesting(event.value, ctx):
            return
        max_size = _module_int(ctx, self.slug, _cti_slug(self.slug), ("max_file_size", "maxfilesize"), 1_000_000)
        content = _fetch_binary(event.value, _http_timeout(ctx), ctx, self.slug, max_size)
        if not content:
            return
        strings_found = self._strings_from_bytes(content, ctx)
        if not strings_found:
            return
        yield _make_event(
            event_type="raw_file_meta_data",
            value="\n".join(strings_found),
            slug=self.slug,
            parent_event=event,
            ctx=ctx,
            risk_score=5,
            confidence=70,
            tags=["binary", "strings"],
            raw_payload={"source_url": event.value, "spiderfoot_parity": True},
        )

    def _looks_interesting(self, value: str, ctx) -> bool:
        allowed = _module_setting(
            ctx,
            self.slug,
            _cti_slug(self.slug),
            ("file_types", "file_extensions", "fileexts"),
            ["png", "gif", "jpg", "jpeg", "tiff", "tif", "ico", "flv", "mp4", "mp3", "avi", "mpg", "mpeg", "dat", "mov", "swf", "exe", "bin"],
        )
        if isinstance(allowed, str):
            ext_list = [item.strip().lower().lstrip(".") for item in allowed.split(",")]
        else:
            ext_list = [str(item or "").strip().lower().lstrip(".") for item in allowed]
        lowered = str(value or "").lower()
        return any(lowered.endswith("." + ext) or f".{ext}?" in lowered for ext in ext_list if ext)

    def _strings_from_bytes(self, content: bytes, ctx) -> list[str]:
        min_word = max(1, _module_int(ctx, self.slug, _cti_slug(self.slug), ("min_string_length", "min_word_size", "minwordsize"), 5))
        max_words = max(1, _module_int(ctx, self.slug, _cti_slug(self.slug), ("max_strings", "max_words", "maxwords"), 100))
        use_dict = _module_bool(ctx, self.slug, _cti_slug(self.slug), ("use_dictionary", "usedict"), True)
        filter_chars = str(_module_setting(ctx, self.slug, _cti_slug(self.slug), ("ignore_characters", "filter_characters", "filterchars"), "#}{|%^&*()=+,;[]~") or "")

        words: list[str] = []
        for match in PRINTABLE_BLOCK_RX.findall(content):
            candidate = match.decode("ascii", errors="ignore").strip()
            if len(candidate) < min_word:
                continue
            if filter_chars and any(char in candidate for char in filter_chars):
                continue
            if use_dict and not self._dictionary_like(candidate):
                continue
            words.append(candidate)
            if len(words) >= max_words:
                break
        return words

    def _dictionary_like(self, candidate: str) -> bool:
        lowered = candidate.lower()
        for word in COMMON_WORDS:
            if lowered.startswith(word) or lowered.endswith(word):
                return True
        return bool(re.search(r"[a-z]{4,}", lowered))


class CompanyNameExtractorModule(BaseModule):
    slug = "company-name-extractor"
    name = "Company Name Extractor"
    watched_types = {"target_web_content", "affiliate_web_content", "domain_whois", "netblock_whois", "affiliate_domain_whois", "ssl_certificate_issued", "domain", "url", "internet_name"}
    produced_types = {"company_name", "affiliate_company_name"}
    requires_key = False

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        content = str(event.value or "")
        source_url = None
        if event.event_type in {"domain", "url", "internet_name"}:
            fetched = _first_page_content(event, ctx, self.slug)
            if not fetched:
                return
            content, source_url, _ = fetched
        if event.event_type == "target_web_content" and _module_bool(ctx, self.slug, _cti_slug(self.slug), ("filter_css_js", "filterjscss"), True):
            actual_source = str(event.raw_payload.get("source_url", "") or "")
            if actual_source.endswith(".js") or actual_source.endswith(".css"):
                return
        for company in self._extract_company_names(content):
            event_type = "affiliate_company_name" if "affiliate" in event.event_type else "company_name"
            yield _make_event(
                event_type=event_type,
                value=company,
                slug=self.slug,
                parent_event=event,
                ctx=ctx,
                risk_score=5,
                confidence=70,
                tags=["company", "entity"],
                raw_payload={"source_url": source_url, "spiderfoot_parity": True},
            )

    def _extract_company_names(self, content: str) -> list[str]:
        chunks: list[str] = []
        for marker in COMPANY_MATCHES:
            start = 0
            while True:
                index = content.find(marker, start)
                if index < 0:
                    break
                chunk_start = max(0, index - 50)
                chunk_end = min(len(content), index + 20)
                chunks.append(content[chunk_start:chunk_end])
                start = index + len(marker)

        found: list[str] = []
        seen: set[str] = set()
        for chunk in chunks:
            for suffix in COMPANY_MATCH_RE:
                for match in re.findall(COMPANY_PREFIX + "(" + suffix + ")" + COMPANY_SUFFIX, chunk, re.M | re.S):
                    pieces = [piece for piece in match if piece]
                    if len(pieces) <= 1:
                        continue
                    full_company = " ".join(
                        piece for piece in pieces
                        if piece and not any(re.match(filter_pattern, piece) for filter_pattern in COMPANY_FILTERS)
                    ).strip()
                    full_company = re.sub(r"\s+", " ", full_company)
                    lowered = full_company.lower()
                    if not full_company or lowered in seen:
                        continue
                    seen.add(lowered)
                    found.append(full_company)
        return found


class CountryNameExtractorModule(BaseModule):
    slug = "country-name-extractor"
    name = "Country Name Extractor"
    watched_types = {
        "iban_number",
        "phone",
        "phone_number",
        "affiliate_domain_name",
        "co_hosted_site_domain",
        "domain",
        "domain_name",
        "similardomain",
        "affiliate_domain_whois",
        "co_hosted_site_domain_whois",
        "domain_whois",
        "geoinfo",
        "physical_address",
    }
    produced_types = {"country_name"}
    requires_key = False

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        countries: list[str] = []
        if event.event_type in {"phone", "phone_number"}:
            country = _country_from_phone(event.value)
            if country:
                countries.append(country)
        elif event.event_type in {"domain", "domain_name", "affiliate_domain_name", "co_hosted_site_domain"}:
            if event.event_type == "affiliate_domain_name":
                allow = _module_bool(ctx, self.slug, _cti_slug(self.slug), ("check_affiliates", "affiliate"), True)
            elif event.event_type == "co_hosted_site_domain":
                allow = _module_bool(ctx, self.slug, _cti_slug(self.slug), ("check_cohosts", "cohosted", "cohosted"), True)
            else:
                allow = True
            if allow:
                country = _country_from_domain(event.value)
                if country:
                    countries.append(country)
        elif event.event_type == "similardomain":
            if _module_bool(ctx, self.slug, _cti_slug(self.slug), ("check_similar_domains", "similardomain"), False):
                country = _country_from_domain(event.value)
                if country:
                    countries.append(country)
        elif event.event_type == "iban_number":
            country = COUNTRY_CODE_MAP.get(str(event.value or "")[:2].upper())
            if country:
                countries.append(country)
        else:
            if event.event_type == "affiliate_domain_whois" and not _module_bool(ctx, self.slug, _cti_slug(self.slug), ("check_affiliates", "affiliate"), True):
                return
            if event.event_type == "co_hosted_site_domain_whois" and not _module_bool(ctx, self.slug, _cti_slug(self.slug), ("check_cohosts", "cohosted"), True):
                return
            countries.extend(_countries_from_text(event.value))

        seen: set[str] = set()
        for country in countries:
            normalized = country.strip()
            if not normalized:
                continue
            lowered = normalized.lower()
            if lowered in seen:
                continue
            seen.add(lowered)
            yield _make_event(
                event_type="country_name",
                value=normalized,
                slug=self.slug,
                parent_event=event,
                ctx=ctx,
                risk_score=0,
                confidence=75,
                tags=["country", "geography"],
                raw_payload={"spiderfoot_parity": True},
            )


class CrossReferencerModule(BaseModule):
    slug = "cross-referencer"
    name = "Cross-Referencer"
    watched_types = {"linked_url_external", "similardomain", "co_hosted_site", "darknet_mention_url", "domain", "url", "internet_name"}
    produced_types = {"affiliate_internet_name", "affiliate_web_content"}
    requires_key = False

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        if event.event_type in {"domain", "url", "internet_name"}:
            fetched = _first_page_content(event, ctx, self.slug)
            if not fetched:
                return
            page_content, base_url, _ = fetched
            for link in _extract_links(page_content, base_url):
                if _is_internal_url(link, ctx.root_target):
                    continue
                for child in self._events_from_candidate(link, event, ctx):
                    yield child
            return

        candidate_url = event.value
        if event.event_type in {"similardomain", "co_hosted_site"}:
            candidate_url = "http://" + str(event.value or "").strip().lower()
        for child in self._events_from_candidate(candidate_url, event, ctx):
            yield child

    def _events_from_candidate(self, candidate_url: str, parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        host = _link_host(candidate_url)
        if not host or _matches_root_target(host, ctx.root_target):
            return []
        if not _host_resolves(host):
            return []
        timeout = _http_timeout(ctx)
        status, body, final_url, _ = _fetch_http(candidate_url, timeout, ctx, self.slug, accept="text/html, text/plain, */*", max_bytes=1_000_000)
        if not status or not body:
            return []
        if not self._mentions_target(body, ctx.root_target):
            if parent_event.event_type == "linked_url_external" and _module_bool(ctx, self.slug, _cti_slug(self.slug), "checkbase", True):
                base_url = self._base_url(candidate_url)
                if base_url and base_url != candidate_url:
                    status, body, final_url, _ = _fetch_http(base_url, timeout, ctx, self.slug, accept="text/html, text/plain, */*", max_bytes=1_000_000)
                    if not status or not body or not self._mentions_target(body, ctx.root_target):
                        return []
                else:
                    return []
            else:
                return []

        affiliate_event = ScanEvent(
            event_type="affiliate_internet_name",
            value=_link_host(final_url or candidate_url),
            source_module=self.slug,
            root_target=ctx.root_target,
            parent_event_id=parent_event.event_id,
            confidence=80,
            risk_score=10,
            tags=["affiliate", "crossref"],
            raw_payload={"source_url": final_url or candidate_url, "spiderfoot_parity": True},
        )
        content_event = ScanEvent(
            event_type="affiliate_web_content",
            value=body,
            source_module=self.slug,
            root_target=ctx.root_target,
            parent_event_id=affiliate_event.event_id,
            confidence=70,
            risk_score=5,
            tags=["affiliate", "content"],
            raw_payload={"source_url": final_url or candidate_url, "spiderfoot_parity": True},
        )
        return [affiliate_event, content_event]

    def _mentions_target(self, body: str, root_target: str) -> bool:
        haystack = str(body or "").lower()
        root = _normalize_indicator(root_target)
        if not root:
            return False
        names = {root}
        keyword = _domain_keyword(root)
        if keyword:
            names.add(keyword)
        return any(name and re.search(rf"([\.\'\/\"\ ]{re.escape(name)}[\.\'\/\"\ ])", haystack) for name in names)

    def _base_url(self, value: str) -> str:
        parsed = urllib.parse.urlparse(value)
        if not parsed.scheme or not parsed.netloc:
            return ""
        return f"{parsed.scheme}://{parsed.netloc}/"


class FileMetadataExtractorModule(BaseModule):
    slug = "file-metadata-extractor"
    name = "File Metadata Extractor"
    watched_types = {"linked_url_internal", "interesting_file", "url"}
    produced_types = {"raw_file_meta_data", "software_used"}
    requires_key = False

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        file_url = str(event.value or "").strip()
        extension = self._matched_extension(file_url, ctx)
        if not extension:
            return
        content = _fetch_binary(
            file_url,
            _module_int(ctx, self.slug, _cti_slug(self.slug), ("download_timeout", "timeout"), 300),
            ctx,
            self.slug,
            10_000_000,
        )
        if not content or len(content) < 32:
            return
        metadata, software = self._parse_metadata(content, extension)
        if not metadata:
            return
        raw_event = _make_event(
            event_type="raw_file_meta_data",
            value=metadata,
            slug=self.slug,
            parent_event=event,
            ctx=ctx,
            risk_score=5,
            confidence=70,
            tags=["file-meta", extension],
            raw_payload={"source_url": file_url, "spiderfoot_parity": True},
        )
        yield raw_event
        for item in software:
            normalized = _normalize_ascii(item).strip()
            if not normalized:
                continue
            yield ScanEvent(
                event_type="software_used",
                value=normalized,
                source_module=self.slug,
                root_target=ctx.root_target,
                parent_event_id=raw_event.event_id,
                confidence=70,
                risk_score=0,
                tags=["file-meta", "software"],
                raw_payload={"source_url": file_url, "spiderfoot_parity": True},
            )

    def _matched_extension(self, value: str, ctx) -> str:
        configured = _module_setting(ctx, self.slug, _cti_slug(self.slug), ("file_extensions", "fileexts"), ["docx", "pptx", "pdf", "jpg", "jpeg", "tiff", "tif"])
        if isinstance(configured, str):
            exts = [item.strip().lstrip(".").lower() for item in configured.split(",")]
        else:
            exts = [str(item or "").strip().lstrip(".").lower() for item in configured]
        lowered = str(value or "").lower()
        for ext in exts:
            if "." + ext in lowered:
                return ext
        return ""

    def _parse_metadata(self, content: bytes, extension: str) -> tuple[str | None, list[str]]:
        if extension == "pdf":
            return _pdf_metadata(content)
        if extension in {"docx", "pptx", "xlsx"}:
            return _office_core_properties(content)
        if extension in {"jpg", "jpeg", "tiff", "tif"}:
            return _image_metadata(content)
        return None, []


class HumanNameExtractorModule(BaseModule):
    slug = "human-name-extractor"
    name = "Human Name Extractor"
    watched_types = {"target_web_content", "email", "email_generic", "domain_whois", "netblock_whois", "raw_rir_data", "raw_file_meta_data", "domain", "url", "internet_name"}
    produced_types = {"human_name"}
    requires_key = False

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        if event.event_type in {"email", "email_generic"} and _module_bool(ctx, self.slug, _cti_slug(self.slug), ("email_to_name", "emailtoname"), True):
            name = self._email_to_name(event.value)
            if name:
                yield _make_event(
                    event_type="human_name",
                    value=name,
                    slug=self.slug,
                    parent_event=event,
                    ctx=ctx,
                    risk_score=5,
                    confidence=85,
                    tags=["human-name", "email-derived"],
                    raw_payload={"spiderfoot_parity": True},
                )
            return

        content = str(event.value or "")
        if event.event_type in {"domain", "url", "internet_name"}:
            fetched = _first_page_content(event, ctx, self.slug)
            if not fetched:
                return
            content, _, _ = fetched

        if event.event_type == "target_web_content" and _module_bool(ctx, self.slug, _cti_slug(self.slug), ("filter_css_js", "filterjscss"), True):
            actual_source = str(event.raw_payload.get("source_url", "") or "")
            if actual_source.endswith(".js") or actual_source.endswith(".css"):
                return

        if event.event_type == "raw_rir_data":
            trusted_sources = {"github", "hunter", "jsonwhois"}
            if event.source_module not in trusted_sources:
                return

        for name in self._extract_names(content, ctx):
            yield _make_event(
                event_type="human_name",
                value=name,
                slug=self.slug,
                parent_event=event,
                ctx=ctx,
                risk_score=5,
                confidence=75,
                tags=["human-name", "content"],
                raw_payload={"spiderfoot_parity": True},
            )

    def _email_to_name(self, value: str) -> str:
        local_part = str(value or "").split("@", 1)[0]
        if "." not in local_part:
            return ""
        parts = [part.strip() for part in local_part.split(".") if part.strip()]
        if len(parts) < 2 or any(re.search(r"\d", part) for part in parts):
            return ""
        return " ".join(part.capitalize() for part in parts)

    def _extract_names(self, content: str, ctx) -> list[str]:
        threshold = max(0, min(100, _module_int(ctx, self.slug, _cti_slug(self.slug), ("algorithm_limit", "algolimit"), 75)))
        matches: list[str] = []
        seen: set[str] = set()
        for first, second in NAME_RX.findall(_strip_html(content)):
            first_lower = first.lower()
            second_lower = second.lower().replace("'s", "").rstrip("'")
            score = 0
            not_in_dict = first_lower not in COMMON_WORDS and second_lower not in COMMON_WORDS
            if not_in_dict:
                score += 75
            if first_lower in COMMON_FIRST_NAMES:
                score += 50
            if len(first_lower) == 2 or len(second_lower) == 2:
                score -= 50
            if not not_in_dict:
                if first_lower in COMMON_WORDS and second_lower not in COMMON_WORDS:
                    score -= 20
                if first_lower not in COMMON_WORDS and second_lower in COMMON_WORDS:
                    score -= 40
            second_clean = second.replace("'s", "").rstrip("'")
            candidate = f"{first} {second_clean}".strip()
            lowered = candidate.lower()
            if score < threshold or lowered in seen:
                continue
            seen.add(lowered)
            matches.append(candidate)
        return matches


class InterestingFileFinderModule(BaseModule):
    slug = "interesting-file-finder"
    name = "Interesting File Finder"
    watched_types = {"linked_url_internal", "url", "domain", "internet_name"}
    produced_types = {"interesting_file"}
    requires_key = False

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        if event.event_type in {"linked_url_internal", "url"}:
            if self._is_interesting(event.value, ctx):
                yield _make_event(
                    event_type="interesting_file",
                    value=event.value,
                    slug=self.slug,
                    parent_event=event,
                    ctx=ctx,
                    risk_score=10,
                    confidence=80,
                    tags=["interesting-file"],
                    raw_payload={"spiderfoot_parity": True},
                )
            return

        fetched = _first_page_content(event, ctx, self.slug)
        if not fetched:
            return
        body, final_url, _ = fetched
        for link in _extract_links(body, final_url):
            if not _is_internal_url(link, ctx.root_target):
                continue
            if not self._is_interesting(link, ctx):
                continue
            yield _make_event(
                event_type="interesting_file",
                value=link,
                slug=self.slug,
                parent_event=event,
                ctx=ctx,
                risk_score=10,
                confidence=80,
                tags=["interesting-file"],
                raw_payload={"source_url": final_url, "spiderfoot_parity": True},
            )

    def _is_interesting(self, value: str, ctx) -> bool:
        lowered = str(value or "").lower()
        return any(lowered.endswith("." + ext) or f".{ext}?" in lowered for ext in _interesting_file_exts(ctx, self.slug))


class JunkFileFinderModule(BaseModule):
    slug = "junk-file-finder"
    name = "Junk File Finder"
    watched_types = {"linked_url_internal", "url", "domain", "internet_name"}
    produced_types = {"junk_file"}
    requires_key = False

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        timeout = _http_timeout(ctx)
        for candidate in self._candidate_urls(event, ctx):
            status, real_url = _head_status(candidate, timeout, ctx, self.slug)
            if status != 200 or real_url != candidate:
                continue
            if not self._valid_404(candidate, timeout, ctx):
                continue
            yield _make_event(
                event_type="junk_file",
                value=candidate,
                slug=self.slug,
                parent_event=event,
                ctx=ctx,
                risk_score=20,
                confidence=70,
                tags=["junk-file"],
                raw_payload={"spiderfoot_parity": True},
            )

    def _candidate_urls(self, event: ScanEvent, ctx) -> list[str]:
        fileexts = _module_setting(ctx, self.slug, _cti_slug(self.slug), "fileexts", ["tmp", "bak", "old"])
        urlexts = _module_setting(ctx, self.slug, _cti_slug(self.slug), ("urlexts", "urlextstry"), ["asp", "php", "jsp"])
        files = _module_setting(ctx, self.slug, _cti_slug(self.slug), "files", ["old", "passwd", ".htaccess", ".htpasswd", "Thumbs.db", "backup"])
        dirs = _module_setting(ctx, self.slug, _cti_slug(self.slug), "dirs", ["zip", "tar.gz", "tgz", "tar"])

        fileexts = [str(item or "").strip().lstrip(".") for item in (fileexts.split(",") if isinstance(fileexts, str) else fileexts)]
        urlexts = [str(item or "").strip().lstrip(".") for item in (urlexts.split(",") if isinstance(urlexts, str) else urlexts)]
        files = [str(item or "").strip() for item in (files.split(",") if isinstance(files, str) else files)]
        dirs = [str(item or "").strip() for item in (dirs.split(",") if isinstance(dirs, str) else dirs)]

        seeds = _seed_urls_for_event(event)
        candidates: set[str] = set()
        for value in seeds:
            parsed = urllib.parse.urlparse(value)
            if not parsed.scheme or not parsed.netloc:
                continue
            path = parsed.path or "/"
            base_dir = path.rsplit("/", 1)[0] + "/"
            root = f"{parsed.scheme}://{parsed.netloc}"
            if any(path.lower().endswith("." + ext) for ext in urlexts):
                clean_path = path.split("?", 1)[0]
                for ext in fileexts:
                    candidates.add(root + clean_path + "." + ext)
            for filename in files:
                candidates.add(root + base_dir + filename)
            if base_dir not in {"/", path, path + "/"}:
                dir_path = base_dir[:-1]
                for extension in dirs:
                    candidates.add(root + dir_path + "." + extension)
        return sorted(candidates)

    def _valid_404(self, url: str, timeout: int, ctx) -> bool:
        probe = url + str(random.SystemRandom().randint(10000, 99999999))
        status, _ = _head_status(probe, timeout, ctx, self.slug)
        return status == 404


class CmSeekModule(BaseModule):
    slug = "cmseek"
    name = "Tool - CMSeeK"
    watched_types = {"domain", "url", "internet_name"}
    produced_types = {"software_used"}
    requires_key = False

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        python_path = str(_module_setting(ctx, self.slug, _cti_slug(self.slug), ("python_path", "pythonpath"), "python3") or "python3").strip()
        cmseek_path = str(_module_setting(ctx, self.slug, _cti_slug(self.slug), ("cmseek_path", "tool_path", "cmseekpath"), "") or "").strip()
        if not cmseek_path:
            ctx.warning("cmseek is enabled but no tool path is configured.", self.slug)
            return
        executable, result_root = _cmseek_paths(cmseek_path)
        if not Path(executable).is_file():
            ctx.warning(f"cmseek executable was not found: {executable}", self.slug)
            return
        if not which(python_path) and not Path(python_path).is_file():
            ctx.warning(f"cmseek Python interpreter was not found: {python_path}", self.slug)
            return

        target = str(event.value or "").strip()
        args = [python_path, executable, "--follow-redirect", "--batch", "-u", target]
        try:
            completed = subprocess.run(args, capture_output=True, text=True, timeout=max(30, _http_timeout(ctx) * 4), check=False)
        except Exception as exc:
            ctx.warning(f"Unable to run CMSeeK: {exc}", self.slug)
            return
        if completed.returncode != 0:
            ctx.warning(f"CMSeeK exited with code {completed.returncode}.", self.slug)
            return
        if "CMS Detection failed" in (completed.stdout or ""):
            return
        parsed = _read_cmseek_result(result_root, target)
        if not parsed:
            ctx.warning(f"CMSeeK result file was not found for {target}.", self.slug)
            return
        software = self._software_from_result(parsed)
        if not software:
            return
        yield _make_event(
            event_type="software_used",
            value=software,
            slug=self.slug,
            parent_event=event,
            ctx=ctx,
            risk_score=5,
            confidence=80,
            tags=["cmseek", "cms"],
            raw_payload={"spiderfoot_parity": True},
        )

    def _software_from_result(self, payload: dict[str, Any]) -> str:
        cms_name = str(payload.get("cms_name", "") or "").strip()
        cms_version = str(payload.get("cms_version", "") or "").strip()
        return " ".join(part for part in [cms_name, cms_version] if part).strip()


__all__ = [
    "AccountFinderModule",
    "BinaryStringExtractorModule",
    "CmSeekModule",
    "CompanyNameExtractorModule",
    "CountryNameExtractorModule",
    "CrossReferencerModule",
    "FileMetadataExtractorModule",
    "HumanNameExtractorModule",
    "InterestingFileFinderModule",
    "JunkFileFinderModule",
]
