"""
SocialEnumerator — reliable, key-free username enumeration across ~700 sites.

Drives checks from the community-maintained WhatsMyName dataset
(https://github.com/WebBreacher/WhatsMyName), vendored at data/wmn-data.json.

Why this over search-engine scraping: it queries each platform *directly* using
that platform's own username-existence detection rule (HTTP status == e_code AND
e_string present in the body), so it is fast, high-yield, and does not rate-limit
the way Google/Bing/DuckDuckGo scraping does.
"""
from __future__ import annotations

import asyncio
import json
import random
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

from utils.logger import get_logger
from utils.cache import FileCache

# Vendored dataset + on-disk response cache live under data/
DATA_DIR = Path(__file__).resolve().parent.parent / "data"
WMN_PATH = DATA_DIR / "wmn-data.json"
CACHE_DIR = DATA_DIR / ".wmn_cache"

NSFW_CATEGORY = "xx NSFW xx"

# WhatsMyName entries whose detection rule matches *every* username (they return
# e_code + e_string even for nonsense handles). Excluded to avoid false positives.
BLOCKLIST = {
    "Arch Linux GitLab",
    "Mastodon API",
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
]

# Minimal fallback so the engine still runs if the vendored dataset is missing.
_FALLBACK_SITES = [
    {"name": "GitHub (User)", "cat": "coding",
     "uri_check": "https://api.github.com/users/{account}", "uri_pretty": "https://github.com/{account}",
     "e_code": 200, "e_string": "\"login\"", "m_code": 404, "m_string": "Not Found"},
    {"name": "GitLab", "cat": "coding", "uri_check": "https://gitlab.com/{account}",
     "e_code": 200, "e_string": "user-profile", "m_code": 404, "m_string": ""},
    {"name": "Reddit", "cat": "social", "uri_check": "https://www.reddit.com/user/{account}/about.json",
     "uri_pretty": "https://www.reddit.com/user/{account}",
     "e_code": 200, "e_string": "\"name\"", "m_code": 404, "m_string": ""},
]


class SocialEnumerator:
    """Checks a username across the WhatsMyName site catalogue."""

    def __init__(
        self,
        timeout: float = 10.0,
        concurrency: int = 100,
        use_cache: bool = True,
        cache_ttl: int = 86400,
        retries: int = 1,
        connect_timeout: float = 5.0,
    ) -> None:
        self.timeout = timeout
        self.concurrency = concurrency
        self.retries = retries
        # Split connect vs read: dead/unreachable hosts fail fast (~5s) instead of
        # burning the full read budget — that's the main speed lever when sweeping
        # ~600 hosts. The read budget stays generous so slow-but-alive platforms
        # aren't misread as absent, and one retry recovers accounts lost to blips.
        self._httpx_timeout = httpx.Timeout(
            connect=min(connect_timeout, timeout), read=timeout,
            write=timeout, pool=timeout,
        )
        self.logger = get_logger()
        self._sites: Optional[List[Dict[str, Any]]] = None
        self.cache = FileCache(cache_dir=str(CACHE_DIR), ttl=cache_ttl) if use_cache else None
        # Per-run reliability telemetry (populated by check_username).
        self.last_stats: Dict[str, int] = {"checked": 0, "errored": 0, "found": 0}

    # ------------------------------------------------------------------ #
    #  Dataset loading / filtering                                        #
    # ------------------------------------------------------------------ #
    def _all_sites(self) -> List[Dict[str, Any]]:
        if self._sites is None:
            try:
                with open(WMN_PATH, "r", encoding="utf-8") as f:
                    self._sites = json.load(f).get("sites", []) or _FALLBACK_SITES
                self.logger.info(f"SocialEnumerator loaded {len(self._sites)} sites from dataset")
            except Exception as e:
                self.logger.warning(f"WhatsMyName dataset unavailable ({e}); using fallback list")
                self._sites = list(_FALLBACK_SITES)
        return self._sites

    def load_sites(
        self,
        include_nsfw: bool = False,
        include_protected: bool = False,
        categories: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Return the site list filtered by category / NSFW / anti-bot protection."""
        sites = []
        cat_filter = set(categories) if categories else None
        for s in self._all_sites():
            cat = s.get("cat", "")
            if s.get("name") in BLOCKLIST:
                continue
            if not include_nsfw and cat == NSFW_CATEGORY:
                continue
            if not include_protected and s.get("protection"):
                continue
            if cat_filter and cat not in cat_filter:
                continue
            if not s.get("uri_check") or not s.get("e_string"):
                continue
            sites.append(s)
        return sites

    def site_count(self, **kwargs) -> int:
        return len(self.load_sites(**kwargs))

    # ------------------------------------------------------------------ #
    #  Per-site detection                                                 #
    # ------------------------------------------------------------------ #
    @staticmethod
    def _apply_account(template: str, site: Dict[str, Any], username: str) -> str:
        account = username
        for ch in site.get("strip_bad_char", "") or "":
            account = account.replace(ch, "")
        return template.replace("{account}", account)

    def _pretty_url(self, site: Dict[str, Any], username: str) -> str:
        template = site.get("uri_pretty") or site.get("uri_check")
        return self._apply_account(template, site, username)

    async def _check_site(
        self, client: httpx.AsyncClient, site: Dict[str, Any], username: str
    ) -> Optional[Dict[str, Any]]:
        name = site.get("name", "?")

        # Cache: only positive/negative existence is cached (keyed by site+username).
        cache_key = f"wmn:{name}:{username.lower()}"
        if self.cache is not None:
            cached = self.cache.get(cache_key)
            if cached is not None:
                return self._result(site, username) if cached else None

        url = self._apply_account(site["uri_check"], site, username)
        headers = {"User-Agent": random.choice(USER_AGENTS), "Accept": "*/*"}
        extra = site.get("headers")
        if isinstance(extra, dict):
            headers.update({k: str(v) for k, v in extra.items()})
        e_string = site.get("e_string") or ""
        post_body = None
        if site.get("post_body"):
            post_body = self._apply_account(str(site["post_body"]), site, username)

        # Retry once on transient network failures — a single timeout/reset would
        # otherwise silently drop a real account (a recall loss, not a false hit).
        exists = False
        errored = False
        for attempt in range(self.retries + 1):
            try:
                if post_body is not None:
                    resp = await client.post(url, content=post_body, headers=headers,
                                             follow_redirects=False)
                else:
                    resp = await client.get(url, headers=headers, follow_redirects=False)
                exists = resp.status_code == site.get("e_code") and e_string in resp.text
                errored = False
                break
            except Exception:
                errored = True
                if attempt < self.retries:
                    continue

        self.last_stats["checked"] += 1
        if errored:
            self.last_stats["errored"] += 1
        elif exists:
            self.last_stats["found"] += 1

        # Only cache confident outcomes: a network error is not evidence of absence.
        if self.cache is not None and not errored:
            self.cache.set(cache_key, exists)
        return self._result(site, username) if exists else None

    def _result(self, site: Dict[str, Any], username: str) -> Dict[str, Any]:
        return {
            "platform": site.get("name", "?"),
            "category": site.get("cat", ""),
            "url": self._pretty_url(site, username),
            "username": username,
            "protected": bool(site.get("protection")),
        }

    # ------------------------------------------------------------------ #
    #  Public API                                                         #
    # ------------------------------------------------------------------ #
    async def check_username(
        self,
        username: str,
        include_nsfw: bool = False,
        include_protected: bool = False,
        categories: Optional[List[str]] = None,
        sites: Optional[List[Dict[str, Any]]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Check `username` across the (filtered) site catalogue and return the
        platforms where it exists: [{platform, category, url, username, protected}].
        """
        username = (username or "").strip()
        if not username:
            return []
        if sites is None:
            sites = self.load_sites(
                include_nsfw=include_nsfw,
                include_protected=include_protected,
                categories=categories,
            )

        self.last_stats = {"checked": 0, "errored": 0, "found": 0}
        sem = asyncio.Semaphore(self.concurrency)

        async def bounded(client, site):
            async with sem:
                return await self._check_site(client, site, username)

        limits = httpx.Limits(max_connections=self.concurrency + 20,
                              max_keepalive_connections=30)
        async with httpx.AsyncClient(
            verify=False, limits=limits, timeout=self._httpx_timeout
        ) as client:
            results = await asyncio.gather(
                *[bounded(client, s) for s in sites], return_exceptions=True
            )

        found: List[Dict[str, Any]] = []
        seen = set()
        for r in results:
            if isinstance(r, dict):
                key = r["url"].rstrip("/").lower()
                if key not in seen:
                    seen.add(key)
                    found.append(r)
        return found
