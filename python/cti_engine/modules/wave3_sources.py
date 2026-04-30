"""Wave 3 no-key source and public-search modules for the CTI engine."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from html import unescape
import json
import re
import urllib.parse
from typing import Any, AsyncIterator

from ..events import ScanEvent
from ..module_base import BaseModule
from ..targets import DOMAIN_RX
from .no_key_reputation import (
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
    _valid_ip,
)
from .wave2_osint import GENERIC_EMAIL_USERS


EMAIL_TEXT_RX = re.compile(r"\b[%A-Z0-9._+\-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
URL_TEXT_RX = re.compile(r"https?://[^\s\"'<>]+", re.I)
HREF_RX = re.compile(r"""href=["']([^"'#]+)["']""", re.I)
ONION_RX = re.compile(r"([a-z2-7]{16,56}\.onion)", re.I)
FLICKR_KEY_RX = re.compile(r'YUI_config\.flickr\.api\.site_key = "([A-Za-z0-9]+)"')
ONION_REDIRECT_RX = re.compile(r"url\.php\?u=(.[^\"']+)[\"']", re.I | re.S)
TORCH_LINK_RX = re.compile(r'<h5><a href="(.*?)"\s+target="_blank">', re.I)
WIKIPEDIA_LINK_RX = re.compile(r"<link>(.*?)</link>", re.I)
PGP_KEY_RX = re.compile(r"(-----BEGIN.*?END.*?BLOCK-----)", re.I | re.S)


def _fetch_json(url: str, timeout: int, ctx, slug: str) -> Any | None:
    content = _fetch_text(url, timeout, ctx, slug, accept="application/json, text/plain, */*")
    if content is None:
        return None
    try:
        return json.loads(content)
    except json.JSONDecodeError as exc:
        ctx.warning(f"{slug} returned invalid JSON: {exc}", slug)
        return None


def _normalize_host(value: str) -> str:
    host = _hostname(value)
    if host:
        return host
    return str(value or "").strip().lower().rstrip(".")


def _root_host(ctx, event: ScanEvent) -> str:
    root = _normalize_host(ctx.root_target)
    if root:
        return root
    return _normalize_host(event.value)


def _matches_target_or_parent(candidate: str, root: str) -> bool:
    candidate = _normalize_host(candidate)
    root = _normalize_host(root)
    if not candidate or not root:
        return False
    if candidate == root:
        return True
    return candidate.endswith("." + root) or root.endswith("." + candidate)


def _looks_like_domain(value: str) -> bool:
    candidate = _normalize_host(value)
    if not candidate or _valid_ip(candidate):
        return False
    return bool(DOMAIN_RX.match(candidate))


def _domain_keyword(value: str) -> str:
    host = _normalize_host(value)
    if not host:
        return ""
    return host.split(".", 1)[0].strip().lower()


def _extract_urls(value: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for match in URL_TEXT_RX.findall(str(value or "")):
        candidate = unescape(match.rstrip(").,;]}>")).strip()
        if candidate and candidate not in seen:
            seen.add(candidate)
            found.append(candidate)
    return found


def _extract_emails(value: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for match in EMAIL_TEXT_RX.findall(str(value or "")):
        candidate = str(match or "").strip().lower()
        if candidate and candidate not in seen:
            seen.add(candidate)
            found.append(candidate)
    return found


def _extract_links_from_html(base_url: str, content: str, allowed_domains: tuple[str, ...] = ()) -> list[str]:
    links: list[str] = []
    seen: set[str] = set()
    for match in HREF_RX.findall(str(content or "")):
        candidate = urllib.parse.urljoin(base_url, unescape(str(match or "").strip()))
        if not candidate or candidate in seen:
            continue
        if allowed_domains and not any(domain in candidate for domain in allowed_domains):
            continue
        seen.add(candidate)
        links.append(candidate)
    return links


def _parse_pattern_list(value: Any, default: list[str]) -> list[str]:
    if isinstance(value, (list, tuple, set)):
        patterns = [str(item or "").strip() for item in value]
    else:
        raw = str(value or "").strip()
        if not raw:
            patterns = []
        else:
            separator = "\n" if "\n" in raw else ","
            patterns = [part.strip() for part in raw.split(separator)]
    filtered = [pattern for pattern in patterns if pattern]
    return filtered or list(default)


def _generic_users(ctx) -> set[str]:
    raw = str(ctx.request.settings.global_settings.get("generic_usernames", "") or "").strip()
    if not raw:
        return set(GENERIC_EMAIL_USERS)
    return {part.strip().lower() for part in raw.split(",") if part.strip()}


def _is_generic_email(value: str, ctx) -> bool:
    local_part = str(value or "").split("@", 1)[0].strip().lower()
    return local_part in _generic_users(ctx)


def _snippet_around(content: str, needle: str, radius: int = 120) -> str | None:
    haystack = str(content or "")
    target = str(needle or "")
    if not haystack or not target:
        return None
    try:
        start = max(0, haystack.index(target) - radius)
    except ValueError:
        return None
    end = min(len(haystack), start + len(target) + (radius * 2))
    return haystack[start:end]


def _extract_pgp_keys(content: str) -> list[str]:
    keys: list[str] = []
    seen: set[str] = set()
    for match in PGP_KEY_RX.findall(str(content or "")):
        candidate = str(match or "").strip()
        if len(candidate) < 300 or candidate in seen:
            continue
        seen.add(candidate)
        keys.append(candidate)
    return keys


class FlickrModule(BaseModule):
    slug = "flickr"
    name = "Flickr"
    watched_types = {"domain"}
    produced_types = {
        "email",
        "email_generic",
        "internet_name",
        "internet_name_unresolved",
        "domain_name",
        "linked_url_internal",
    }
    requires_key = False

    HOME_URL = "https://www.flickr.com/"
    SEARCH_URL = "https://api.flickr.com/services/rest?{query}"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        timeout = _http_timeout(ctx)
        api_key = self._retrieve_api_key(timeout, ctx)
        if not api_key:
            ctx.warning("Failed to obtain Flickr API key.", self.slug)
            return

        max_pages = max(1, _module_int(
            ctx,
            self.slug,
            _cti_slug(self.slug),
            ("max_pages", "maxpages"),
            20,
        ))
        per_page = max(1, _module_int(
            ctx,
            self.slug,
            _cti_slug(self.slug),
            ("max_results_per_page", "per_page"),
            100,
        ))
        dns_resolve = _module_bool(
            ctx,
            self.slug,
            _cti_slug(self.slug),
            "dns_resolve",
            True,
        )

        seen_pairs: set[tuple[str, str]] = set()
        total_pages = max_pages
        page = 1
        while page <= total_pages:
            payload = self._query(event.value, api_key, page, per_page, timeout, ctx)
            if not isinstance(payload, dict):
                return
            if str(payload.get("stat", "") or "").lower() != "ok":
                ctx.info("Flickr returned no search results.", self.slug)
                return

            photos = payload.get("photos")
            if not isinstance(photos, dict):
                return

            result_pages = int(photos.get("pages", 0) or 0)
            if result_pages > 0:
                total_pages = min(total_pages, result_pages)
            if "max_allowed_pages" in photos:
                total_pages = min(total_pages, int(photos.get("max_allowed_pages", 0) or total_pages))

            for child in self._events_from_photo_rows(
                photos.get("photo") or [],
                event,
                ctx,
                dns_resolve=dns_resolve,
            ):
                pair = (child.event_type, child.value)
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)
                yield child

            page += 1

    def _retrieve_api_key(self, timeout: int, ctx) -> str:
        content = _fetch_text(self.HOME_URL, timeout, ctx, self.slug, accept="text/html, */*")
        if not content:
            return ""
        match = FLICKR_KEY_RX.search(content)
        return str(match.group(1) if match else "").strip()

    def _query(self, query: str, api_key: str, page: int, per_page: int, timeout: int, ctx) -> dict[str, Any] | None:
        params = {
            "sort": "relevance",
            "parse_tags": "1",
            "content_type": "7",
            "extras": "description,owner_name,path_alias,realname",
            "hermes": "1",
            "hermesClient": "1",
            "reqId": "",
            "nojsoncallback": "1",
            "viewerNSID": "",
            "method": "flickr.photos.search",
            "csrf": "",
            "lang": "en-US",
            "per_page": str(per_page),
            "page": str(page),
            "text": query,
            "api_key": api_key,
            "format": "json",
        }
        endpoint = self.SEARCH_URL.format(query=urllib.parse.urlencode(params))
        payload = _fetch_json(endpoint, timeout, ctx, self.slug)
        if payload is None:
            return None
        return payload if isinstance(payload, dict) else None

    def _events_from_photo_rows(
        self,
        rows: list[dict[str, Any]],
        parent_event: ScanEvent,
        ctx,
        *,
        dns_resolve: bool,
    ) -> list[ScanEvent]:
        events: list[ScanEvent] = []
        seen_values: set[tuple[str, str]] = set()
        root = _root_host(ctx, parent_event)
        hosts: set[str] = set()

        for row in rows:
            row_text = str(row or "")
            for email in _extract_emails(row_text):
                mail_domain = email.split("@", 1)[1]
                if not _matches_target_or_parent(mail_domain, root):
                    continue
                event_type = "email_generic" if _is_generic_email(email, ctx) else "email"
                pair = (event_type, email)
                if pair in seen_values:
                    continue
                seen_values.add(pair)
                events.append(_make_event(
                    event_type=event_type,
                    value=email,
                    slug=self.slug,
                    parent_event=parent_event,
                    ctx=ctx,
                    risk_score=6,
                    confidence=75,
                    tags=["flickr", "email"],
                    raw_payload={"row": row, "spiderfoot_parity": True},
                ))

            for link in _extract_urls(row_text):
                host = _normalize_host(link)
                if not host or not _matches_target_or_parent(host, root):
                    continue
                pair = ("linked_url_internal", link)
                if pair in seen_values:
                    continue
                seen_values.add(pair)
                events.append(_make_event(
                    event_type="linked_url_internal",
                    value=link,
                    slug=self.slug,
                    parent_event=parent_event,
                    ctx=ctx,
                    risk_score=5,
                    confidence=75,
                    tags=["flickr", "url"],
                    raw_payload={"row": row, "spiderfoot_parity": True},
                ))
                hosts.add(host)

        for host in sorted(hosts):
            if dns_resolve and not _host_resolves(host):
                event_type = "internet_name_unresolved"
            else:
                event_type = "internet_name"
            pair = (event_type, host)
            if pair in seen_values:
                continue
            seen_values.add(pair)
            host_event = _make_event(
                event_type=event_type,
                value=host,
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=5,
                confidence=70,
                tags=["flickr", "host"],
                raw_payload={"spiderfoot_parity": True},
            )
            events.append(host_event)
            if event_type == "internet_name" and _looks_like_domain(host):
                pair = ("domain_name", host)
                if pair not in seen_values:
                    seen_values.add(pair)
                    events.append(_make_event(
                        event_type="domain_name",
                        value=host,
                        slug=self.slug,
                        parent_event=parent_event,
                        ctx=ctx,
                        risk_score=4,
                        confidence=70,
                        tags=["flickr", "domain"],
                        raw_payload={"spiderfoot_parity": True},
                    ))

        return events


class GitHubModule(BaseModule):
    slug = "github"
    name = "GitHub"
    watched_types = {"domain", "username", "social_media"}
    produced_types = {"raw_rir_data", "geoinfo", "public_code_repo"}
    requires_key = False

    REPO_SEARCH_URL = "https://api.github.com/search/repositories?q={query}"
    USER_SEARCH_URL = "https://api.github.com/search/users?q={query}"
    USER_URL = "https://api.github.com/users/{username}"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        names_only = _module_bool(
            ctx,
            self.slug,
            _cti_slug(self.slug),
            ("match_name_only", "namesonly"),
            True,
        )
        seen_pairs: set[tuple[str, str]] = set()

        if event.event_type == "social_media":
            username = self._username_from_social_profile(event.value)
            if not username:
                return
            payload = _fetch_json(
                self.USER_URL.format(username=urllib.parse.quote(username, safe="")),
                _http_timeout(ctx),
                ctx,
                self.slug,
            )
            for child in self._events_from_user_profile(payload, event, ctx):
                pair = (child.event_type, child.value)
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)
                yield child
            return

        username = event.value if event.event_type == "username" else _domain_keyword(event.value)
        if not username:
            return

        timeout = _http_timeout(ctx)
        repo_payload = _fetch_json(
            self.REPO_SEARCH_URL.format(query=urllib.parse.quote(username, safe="")),
            timeout,
            ctx,
            self.slug,
        )
        for child in self._events_from_repo_items(
            repo_payload.get("items") if isinstance(repo_payload, dict) else [],
            username,
            event,
            ctx,
            names_only=names_only,
            strict_user=False,
        ):
            pair = (child.event_type, child.value)
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            yield child

        user_payload = _fetch_json(
            self.USER_SEARCH_URL.format(query=urllib.parse.quote(username, safe="")),
            timeout,
            ctx,
            self.slug,
        )
        if not isinstance(user_payload, dict):
            return
        for item in user_payload.get("items") or []:
            if not isinstance(item, dict):
                continue
            repos_url = str(item.get("repos_url", "") or "").strip()
            if not repos_url:
                continue
            repo_list = _fetch_json(repos_url, timeout, ctx, self.slug)
            for child in self._events_from_repo_items(
                repo_list if isinstance(repo_list, list) else [],
                username,
                event,
                ctx,
                names_only=names_only,
                strict_user=(event.event_type == "username"),
            ):
                pair = (child.event_type, child.value)
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)
                yield child

    def _username_from_social_profile(self, value: str) -> str:
        candidate = str(value or "").strip()
        if ": " not in candidate:
            return ""
        network, url_value = candidate.split(": ", 1)
        if network.strip().lower() != "github":
            return ""
        clean_url = url_value.replace("<SFURL>", "").replace("</SFURL>", "").strip().rstrip("/")
        parts = [part for part in clean_url.split("/") if part]
        return parts[-1].strip() if parts else ""

    def _build_repo_info(self, item: dict[str, Any]) -> str | None:
        name = item.get("name")
        html_url = item.get("html_url")
        description = item.get("description")
        if name is None or html_url is None or description is None:
            return None
        return "\n".join([
            f"Name: {name}",
            f"URL: {html_url}",
            f"Description: {description}",
        ])

    def _events_from_user_profile(self, payload: Any, parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        if not isinstance(payload, dict):
            return []
        if not payload.get("login") or not payload.get("name"):
            return []

        events = [_make_event(
            event_type="raw_rir_data",
            value=f"Possible full name: {payload.get('name')}",
            slug=self.slug,
            parent_event=parent_event,
            ctx=ctx,
            risk_score=5,
            confidence=65,
            tags=["github", "profile", "name"],
            raw_payload={"profile": payload, "spiderfoot_parity": True},
        )]

        location = str(payload.get("location", "") or "").strip()
        if 3 <= len(location) <= 100:
            events.append(_make_event(
                event_type="geoinfo",
                value=location,
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=5,
                confidence=60,
                tags=["github", "profile", "location"],
                raw_payload={"profile": payload, "spiderfoot_parity": True},
            ))
        return events

    def _events_from_repo_items(
        self,
        items: Any,
        username: str,
        parent_event: ScanEvent,
        ctx,
        *,
        names_only: bool,
        strict_user: bool,
    ) -> list[ScanEvent]:
        if not isinstance(items, list):
            return []
        events: list[ScanEvent] = []
        target = str(username or "").strip().lower()
        seen: set[str] = set()
        for item in items:
            if not isinstance(item, dict):
                continue
            repo_info = self._build_repo_info(item)
            if repo_info is None:
                continue
            repo_name = str(item.get("name", "") or "").strip().lower()
            if names_only and repo_name != target:
                continue
            html_url = str(item.get("html_url", "") or "")
            if strict_user and f"/{target}/" not in html_url.lower():
                continue
            if repo_info in seen:
                continue
            seen.add(repo_info)
            events.append(_make_event(
                event_type="public_code_repo",
                value=repo_info,
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=10,
                confidence=75,
                tags=["github", "repository", "code"],
                raw_payload={"item": item, "spiderfoot_parity": True},
            ))
        return events


class OnionSearchEngineModule(BaseModule):
    slug = "onionsearchengine"
    name = "Onionsearchengine.com"
    watched_types = {"domain", "email", "username"}
    produced_types = {"darknet_mention_url", "darknet_mention_content"}
    requires_key = False

    SEARCH_URL = "https://onionsearchengine.com/search.php?{query}"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        if event.event_type == "username" and not _module_bool(
            ctx,
            self.slug,
            _cti_slug(self.slug),
            ("search_names", "fullnames"),
            True,
        ):
            return

        timeout = max(1, _module_int(
            ctx,
            self.slug,
            _cti_slug(self.slug),
            ("timeout_seconds", "timeout"),
            10,
        ))
        max_pages = max(1, _module_int(
            ctx,
            self.slug,
            _cti_slug(self.slug),
            ("max_pages",),
            20,
        ))
        fetch_darknet = _module_bool(
            ctx,
            self.slug,
            _cti_slug(self.slug),
            ("fetch_darknet", "fetchlinks"),
            True,
        )
        blacklist_patterns = _parse_pattern_list(
            _module_setting(
                ctx,
                self.slug,
                _cti_slug(self.slug),
                ("exclude_patterns", "blacklist"),
                [".*://relate.*"],
            ),
            [".*://relate.*"],
        )

        seen_pairs: set[tuple[str, str]] = set()
        keep_going = True
        page = 1
        while keep_going and page <= max_pages:
            params = {
                "search": f"\"{event.value}\"",
                "submit": "Search",
                "page": str(page),
            }
            endpoint = self.SEARCH_URL.format(query=urllib.parse.urlencode(params))
            content = _fetch_text(endpoint, timeout, ctx, self.slug, accept="text/html, */*")
            if not content:
                ctx.info("No results returned from onionsearchengine.com.", self.slug)
                return

            page += 1
            if "url.php?u=" not in content:
                if "you didn't submit a keyword" in content.lower():
                    continue
                return
            keep_going = "forward >" in content.lower()

            for child in self._events_from_search_page(
                content,
                event,
                ctx,
                timeout=timeout,
                fetch_darknet=fetch_darknet,
                blacklist_patterns=blacklist_patterns,
            ):
                pair = (child.event_type, child.value)
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)
                yield child

    def _events_from_search_page(
        self,
        content: str,
        parent_event: ScanEvent,
        ctx,
        *,
        timeout: int,
        fetch_darknet: bool,
        blacklist_patterns: list[str],
    ) -> list[ScanEvent]:
        events: list[ScanEvent] = []
        target = str(parent_event.value or "")
        for match in ONION_REDIRECT_RX.findall(str(content or "")):
            link = urllib.parse.unquote(str(match or "").strip())
            if not link:
                continue
            if any(re.match(pattern, link, re.I) for pattern in blacklist_patterns):
                continue
            if not ONION_RX.search(_normalize_host(link)):
                continue
            if not fetch_darknet:
                events.append(self._darknet_url_event(link, parent_event, ctx))
                continue
            page = _fetch_text(link, timeout, ctx, self.slug, accept="text/html, */*")
            if not page or target not in page:
                continue
            url_event = self._darknet_url_event(link, parent_event, ctx)
            events.append(url_event)
            snippet = _snippet_around(page, target)
            if snippet:
                events.append(_make_event(
                    event_type="darknet_mention_content",
                    value=f"...{snippet}...",
                    slug=self.slug,
                    parent_event=url_event,
                    ctx=ctx,
                    risk_score=25,
                    confidence=70,
                    tags=["onionsearchengine", "darknet", "mention", "content"],
                    raw_payload={"url": link, "spiderfoot_parity": True},
                ))
        return events

    def _darknet_url_event(self, link: str, parent_event: ScanEvent, ctx) -> ScanEvent:
        return _make_event(
            event_type="darknet_mention_url",
            value=link,
            slug=self.slug,
            parent_event=parent_event,
            ctx=ctx,
            risk_score=20,
            confidence=75,
            tags=["onionsearchengine", "darknet", "mention", "url"],
            raw_payload={"url": link, "spiderfoot_parity": True},
        )


class TorchModule(BaseModule):
    slug = "torch"
    name = "TORCH"
    watched_types = {"domain", "email", "username"}
    produced_types = {"darknet_mention_url", "darknet_mention_content"}
    requires_key = False

    HOME_URL = "http://torchdeedp3i2jigzjdmfpn5ttjhthh5wbmda2rr3jvqjg5p77c54dqd.onion/"
    SEARCH_URL = "http://torchdeedp3i2jigzjdmfpn5ttjhthh5wbmda2rr3jvqjg5p77c54dqd.onion/search?{query}"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        if event.event_type == "username" and not _module_bool(
            ctx,
            self.slug,
            _cti_slug(self.slug),
            ("search_names", "fullnames"),
            True,
        ):
            return

        timeout = max(_http_timeout(ctx), 15)
        max_pages = max(1, _module_int(
            ctx,
            self.slug,
            _cti_slug(self.slug),
            ("max_pages", "pages"),
            20,
        ))
        fetch_darknet = _module_bool(
            ctx,
            self.slug,
            _cti_slug(self.slug),
            ("fetch_darknet", "fetchlinks"),
            True,
        )

        home_page = _fetch_text(self.HOME_URL, timeout, ctx, self.slug, accept="text/html, */*")
        if not home_page:
            ctx.info("Couldn't connect to TORCH, it might be down.", self.slug)
            return

        seen_pairs: set[tuple[str, str]] = set()
        page_number = 0
        while page_number < max_pages:
            params = {"action": "search", "query": event.value}
            if page_number > 0:
                params["page"] = str(page_number)
            endpoint = self.SEARCH_URL.format(query=urllib.parse.urlencode(params))
            content = _fetch_text(endpoint, timeout, ctx, self.slug, accept="text/html, */*")
            if not content:
                ctx.info("No results returned from TORCH.", self.slug)
                return

            page_number += 1
            page_events = self._events_from_search_page(
                content,
                event,
                ctx,
                timeout=timeout,
                fetch_darknet=fetch_darknet,
            )
            if not page_events:
                return
            for child in page_events:
                pair = (child.event_type, child.value)
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)
                yield child

    def _events_from_search_page(
        self,
        content: str,
        parent_event: ScanEvent,
        ctx,
        *,
        timeout: int,
        fetch_darknet: bool,
    ) -> list[ScanEvent]:
        events: list[ScanEvent] = []
        target = str(parent_event.value or "")
        for link in TORCH_LINK_RX.findall(str(content or "")):
            candidate = str(link or "").strip()
            if not ONION_RX.search(_normalize_host(candidate)):
                continue
            if not fetch_darknet:
                events.append(self._darknet_url_event(candidate, parent_event, ctx))
                continue
            page = _fetch_text(candidate, timeout, ctx, self.slug, accept="text/html, */*")
            if not page or target not in page:
                continue
            url_event = self._darknet_url_event(candidate, parent_event, ctx)
            events.append(url_event)
            snippet = _snippet_around(page, target)
            if snippet:
                events.append(_make_event(
                    event_type="darknet_mention_content",
                    value=f"...{snippet}...",
                    slug=self.slug,
                    parent_event=url_event,
                    ctx=ctx,
                    risk_score=25,
                    confidence=70,
                    tags=["torch", "darknet", "mention", "content"],
                    raw_payload={"url": candidate, "spiderfoot_parity": True},
                ))
        return events

    def _darknet_url_event(self, link: str, parent_event: ScanEvent, ctx) -> ScanEvent:
        return _make_event(
            event_type="darknet_mention_url",
            value=link,
            slug=self.slug,
            parent_event=parent_event,
            ctx=ctx,
            risk_score=20,
            confidence=75,
            tags=["torch", "darknet", "mention", "url"],
            raw_payload={"url": link, "spiderfoot_parity": True},
        )


class WikileaksModule(BaseModule):
    slug = "wikileaks"
    name = "Wikileaks"
    watched_types = {"domain", "email", "username"}
    produced_types = {"leaksite_url", "leaksite_content"}
    requires_key = False

    SEARCH_BASE = "https://search.wikileaks.org/"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        days_back = _module_int(
            ctx,
            self.slug,
            _cti_slug(self.slug),
            ("ignore_older_days", "daysback"),
            365,
        )
        include_external = _module_bool(
            ctx,
            self.slug,
            _cti_slug(self.slug),
            ("include_external_leaks", "external"),
            True,
        )
        max_date = ""
        if days_back > 0:
            max_date = (datetime.now(timezone.utc) - timedelta(days=days_back)).strftime("%Y-%m-%d")

        timeout = _http_timeout(ctx)
        page = 0
        seen_pairs: set[tuple[str, str]] = set()
        content = self._fetch_search_page(event.value, max_date, include_external, page, timeout, ctx)
        while content:
            search_url = self._search_url(event.value, max_date, include_external, page)
            for child in self._events_from_search_page(search_url, content, event, ctx):
                pair = (child.event_type, child.value)
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)
                yield child
            if "page=" not in content or page > 50:
                return
            page += 1
            content = self._fetch_search_page(event.value, max_date, include_external, page, timeout, ctx)

    def _search_url(self, target: str, max_date: str, include_external: bool, page: int) -> str:
        params = {
            "query": f"\"{target}\"",
            "released_date_start": max_date,
            "include_external_sources": "True" if include_external else "",
            "new_search": "True",
            "order_by": "most_relevant",
        }
        if page > 0:
            params["page"] = str(page)
        return self.SEARCH_BASE + "?" + urllib.parse.urlencode(params) + "#results"

    def _fetch_search_page(self, target: str, max_date: str, include_external: bool, page: int, timeout: int, ctx) -> str | None:
        url = self._search_url(target, max_date, include_external, page)
        return _fetch_text(url, timeout, ctx, self.slug, accept="text/html, */*")

    def _events_from_search_page(self, search_url: str, content: str, parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        events: list[ScanEvent] = []
        seen: set[str] = set()
        for link in _extract_links_from_html(search_url, content, ("wikileaks.org", "cryptome.org")):
            if link in seen:
                continue
            seen.add(link)
            if "search.wikileaks.org/" in link:
                continue
            if "wikileaks.org/" not in link and "cryptome.org/" not in link:
                continue
            if link.count("/") < 4:
                continue
            if link.endswith(".js") or link.endswith(".css"):
                continue
            events.append(_make_event(
                event_type="leaksite_url",
                value=link,
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=35,
                confidence=70,
                tags=["wikileaks", "leak", "url"],
                raw_payload={"search_url": search_url, "spiderfoot_parity": True},
            ))
        return events


class WikipediaEditsModule(BaseModule):
    slug = "wikipedia-edits"
    name = "Wikipedia Edits"
    watched_types = {"ip", "username"}
    produced_types = {"wikipedia_page_edit"}
    requires_key = False

    API_URL = "https://en.wikipedia.org/w/api.php?{query}"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        actor = self._normalize_actor(event.value, event.event_type)
        if not actor:
            return
        days_limit = _module_int(
            ctx,
            self.slug,
            _cti_slug(self.slug),
            ("max_age_days", "days_limit"),
            365,
        )
        params = {"action": "feedcontributions", "user": actor}
        if days_limit > 0:
            dt = datetime.now(timezone.utc) - timedelta(days=days_limit)
            params["year"] = dt.strftime("%Y")
            params["month"] = dt.strftime("%m")

        content = _fetch_text(
            self.API_URL.format(query=urllib.parse.urlencode(params)),
            _http_timeout(ctx),
            ctx,
            self.slug,
            accept="application/xml, text/xml, text/html, */*",
        )
        if not content:
            return
        for child in self._events_from_payload(content, event, ctx):
            yield child

    def _normalize_actor(self, value: str, event_type: str) -> str:
        actor = str(value or "").strip()
        if event_type == "username":
            if len(actor) >= 2 and ((actor.startswith('"') and actor.endswith('"')) or (actor.startswith("'") and actor.endswith("'"))):
                actor = actor[1:-1].strip()
            actor = actor.lstrip("@").strip()
        try:
            return actor.encode("raw_unicode_escape").decode("ascii", errors="replace")
        except Exception:
            return actor

    def _events_from_payload(self, content: str, parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        events: list[ScanEvent] = []
        seen: set[str] = set()
        for match in WIKIPEDIA_LINK_RX.findall(str(content or "")):
            link = unescape(str(match or "").strip())
            if not link or "Special:Contributions" in link or link in seen:
                continue
            seen.add(link)
            events.append(_make_event(
                event_type="wikipedia_page_edit",
                value=link,
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=5,
                confidence=70,
                tags=["wikipedia", "edit", "history"],
                raw_payload={"spiderfoot_parity": True},
            ))
        return events


class PgpKeyServersModule(BaseModule):
    slug = "pgp-keyservers"
    name = "PGP Key Servers"
    watched_types = {"domain", "internet_name", "email"}
    produced_types = {"email", "email_generic", "affiliate_email", "pgp_key"}
    requires_key = False

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        timeout = _http_timeout(ctx)
        search_urls = [
            str(_module_setting(ctx, self.slug, _cti_slug(self.slug), ("pgp_email_url", "keyserver_search1"), "") or "").strip(),
            str(_module_setting(ctx, self.slug, _cti_slug(self.slug), ("pgp_email_url_2", "keyserver_search2"), "") or "").strip(),
        ]
        fetch_urls = [
            str(_module_setting(ctx, self.slug, _cti_slug(self.slug), ("pgp_key_url", "keyserver_fetch1"), "") or "").strip(),
            str(_module_setting(ctx, self.slug, _cti_slug(self.slug), ("pgp_key_url_2", "keyserver_fetch2"), "") or "").strip(),
        ]
        retrieve_keys = _module_bool(
            ctx,
            self.slug,
            _cti_slug(self.slug),
            "retrieve_keys",
            True,
        )

        seen_pairs: set[tuple[str, str]] = set()
        if event.event_type in {"domain", "internet_name"}:
            for base_url in search_urls:
                if not base_url:
                    continue
                content = _fetch_text(
                    base_url + urllib.parse.quote(event.value, safe=""),
                    timeout,
                    ctx,
                    self.slug,
                    accept="text/html, text/plain, */*",
                )
                if not content:
                    continue
                for child in self._events_from_domain_content(content, event, ctx):
                    pair = (child.event_type, child.value)
                    if pair in seen_pairs:
                        continue
                    seen_pairs.add(pair)
                    yield child
                return
            return

        if event.event_type == "email" and retrieve_keys:
            for base_url in fetch_urls:
                if not base_url:
                    continue
                content = _fetch_text(
                    base_url + urllib.parse.quote(event.value, safe=""),
                    timeout,
                    ctx,
                    self.slug,
                    accept="text/html, text/plain, */*",
                )
                if not content:
                    continue
                for child in self._events_from_key_content(content, event, ctx):
                    pair = (child.event_type, child.value)
                    if pair in seen_pairs:
                        continue
                    seen_pairs.add(pair)
                    yield child
                return

    def _events_from_domain_content(self, content: str, parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        events: list[ScanEvent] = []
        root = _root_host(ctx, parent_event)
        seen: set[tuple[str, str]] = set()
        for email in _extract_emails(content):
            mail_domain = email.split("@", 1)[1]
            if _matches_root_target(mail_domain, root):
                event_type = "email_generic" if _is_generic_email(email, ctx) else "email"
            else:
                event_type = "affiliate_email"
            pair = (event_type, email)
            if pair in seen:
                continue
            seen.add(pair)
            events.append(_make_event(
                event_type=event_type,
                value=email,
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=7 if event_type == "affiliate_email" else 5,
                confidence=75,
                tags=["pgp", "email", "keyserver"],
                raw_payload={"spiderfoot_parity": True},
            ))
        return events

    def _events_from_key_content(self, content: str, parent_event: ScanEvent, ctx) -> list[ScanEvent]:
        return [
            _make_event(
                event_type="pgp_key",
                value=key,
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=10,
                confidence=80,
                tags=["pgp", "key", "keyserver"],
                raw_payload={"spiderfoot_parity": True},
            )
            for key in _extract_pgp_keys(content)
        ]


class CrxCavatorModule(BaseModule):
    slug = "crxcavator"
    name = "CRXcavator"
    watched_types = {"domain"}
    produced_types = {
        "appstore_entry",
        "internet_name",
        "internet_name_unresolved",
        "affiliate_internet_name",
        "affiliate_internet_name_unresolved",
        "linked_url_internal",
        "physical_address",
        "raw_rir_data",
    }
    requires_key = False

    SEARCH_URL = "https://api.crxcavator.io/v1/search?q={query}"
    REPORT_URL = "https://api.crxcavator.io/v1/report/{extension_id}"

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        keyword = _domain_keyword(event.value)
        if not keyword:
            return

        timeout = _http_timeout(ctx)
        verify_hosts = _module_bool(
            ctx,
            self.slug,
            _cti_slug(self.slug),
            ("verify_hostnames", "verify"),
            True,
        )
        search_payload = _fetch_json(
            self.SEARCH_URL.format(query=urllib.parse.quote(keyword, safe="")),
            timeout,
            ctx,
            self.slug,
        )
        if not isinstance(search_payload, list) or not search_payload:
            ctx.info(f"No results found for {keyword}", self.slug)
            return

        yield _make_event(
            event_type="raw_rir_data",
            value=json.dumps(search_payload),
            slug=self.slug,
            parent_event=event,
            ctx=ctx,
            risk_score=5,
            confidence=70,
            tags=["crxcavator", "search", "raw"],
            raw_payload={"search": search_payload, "spiderfoot_parity": True},
        )

        seen_pairs: set[tuple[str, str]] = set()
        for row in search_payload:
            if not isinstance(row, dict):
                continue
            extension_id = str(row.get("extension_id", "") or "").strip()
            if not extension_id or "@" in extension_id:
                continue
            report_payload = _fetch_json(
                self.REPORT_URL.format(extension_id=urllib.parse.quote(extension_id, safe="")),
                timeout,
                ctx,
                self.slug,
            )
            if not isinstance(report_payload, list) or not report_payload:
                continue

            raw_report = json.dumps(report_payload)
            pair = ("raw_rir_data", raw_report)
            if pair not in seen_pairs:
                seen_pairs.add(pair)
                yield _make_event(
                    event_type="raw_rir_data",
                    value=raw_report,
                    slug=self.slug,
                    parent_event=event,
                    ctx=ctx,
                    risk_score=5,
                    confidence=70,
                    tags=["crxcavator", "report", "raw"],
                    raw_payload={"report": report_payload, "spiderfoot_parity": True},
                )

            for child in self._events_from_extension_payload(
                extension_id,
                report_payload,
                event,
                ctx,
                verify_hosts=verify_hosts,
            ):
                pair = (child.event_type, child.value)
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)
                yield child

    def _events_from_extension_payload(
        self,
        extension_id: str,
        payload: list[dict[str, Any]],
        parent_event: ScanEvent,
        ctx,
        *,
        verify_hosts: bool,
    ) -> list[ScanEvent]:
        events: list[ScanEvent] = []
        urls: set[str] = set()
        hosts: set[str] = set()
        locations: set[str] = set()
        root = _root_host(ctx, parent_event)

        for extension in payload:
            if not isinstance(extension, dict):
                continue
            data = extension.get("data")
            if not isinstance(data, dict):
                continue
            manifest = data.get("manifest")
            webstore = data.get("webstore")
            if not isinstance(manifest, dict) or not isinstance(webstore, dict):
                continue

            version = str(manifest.get("version", "") or "").strip()
            name = str(webstore.get("name", "") or "").strip()
            if not version or not name:
                continue

            privacy_policy = str(webstore.get("privacy_policy", "") or "").strip()
            support_site = str(webstore.get("support_site", "") or "").strip()
            offered_by = str(webstore.get("offered_by", "") or "").strip()
            website = str(webstore.get("website", "") or "").strip()
            candidate_urls = [privacy_policy, support_site, website, offered_by]
            if not any(candidate_urls):
                continue

            candidate_hosts = [_normalize_host(url) for url in candidate_urls if url]
            if not any(_matches_target_or_parent(host, root) for host in candidate_hosts if host):
                continue

            app_entry = (
                f"{name} {version}\n"
                f"<SFURL>https://chrome.google.com/webstore/detail/{extension_id}</SFURL>"
            )
            events.append(_make_event(
                event_type="appstore_entry",
                value=app_entry,
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=8,
                confidence=75,
                tags=["crxcavator", "extension", "appstore"],
                raw_payload={"extension": extension, "spiderfoot_parity": True},
            ))

            for url in candidate_urls:
                if not url:
                    continue
                host = _normalize_host(url)
                if not host:
                    continue
                hosts.add(host)
                if _matches_target_or_parent(host, root):
                    urls.add(url)

            address = str(webstore.get("address", "") or "").strip()
            if len(address) > 10:
                locations.add(address)

        for url in sorted(urls):
            events.append(_make_event(
                event_type="linked_url_internal",
                value=url,
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=5,
                confidence=75,
                tags=["crxcavator", "url"],
                raw_payload={"spiderfoot_parity": True},
            ))

        for host in sorted(hosts):
            target_related = _matches_target_or_parent(host, root)
            if target_related:
                event_type = "internet_name"
            else:
                event_type = "affiliate_internet_name"
            if verify_hosts and not _host_resolves(host):
                event_type += "_unresolved"
            events.append(_make_event(
                event_type=event_type,
                value=host,
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=8 if target_related else 10,
                confidence=70,
                tags=["crxcavator", "host"],
                raw_payload={"spiderfoot_parity": True},
            ))

        for location in sorted(locations):
            events.append(_make_event(
                event_type="physical_address",
                value=location,
                slug=self.slug,
                parent_event=parent_event,
                ctx=ctx,
                risk_score=10,
                confidence=70,
                tags=["crxcavator", "address"],
                raw_payload={"spiderfoot_parity": True},
            ))

        return events


__all__ = [
    "CrxCavatorModule",
    "FlickrModule",
    "GitHubModule",
    "OnionSearchEngineModule",
    "PgpKeyServersModule",
    "TorchModule",
    "WikipediaEditsModule",
    "WikileaksModule",
]
