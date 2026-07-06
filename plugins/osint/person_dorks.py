"""
Web Profile Discovery Plugin — Finds a person's public social profiles.

Strategy (works without API keys):
  1. Direct username enumeration across ~600 sites (WhatsMyName dataset) for
     handles derived from the name — reliable, high-yield, does not rate-limit.
  2. Multi-engine web search (DuckDuckGo + Bing) for LinkedIn/Facebook/Instagram/X.
  3. GitHub name API for rich name/bio context.
Every result carries a confidence tier (Confirmed / Likely / Candidate).
Optional Google CSE / SerpApi enrichment is layered on when keys are present.
"""
import re
from plugins.base import PluginBase, PluginResult, PluginCategory, ApiType

_EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
_PHONE_RE = re.compile(r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}')


class WebProfileDiscoveryPlugin(PluginBase):
    name = "Web Profile Discovery"
    description = "Finds a person's social profiles across ~600 platforms via username enumeration + web search, ranked by confidence."
    category = PluginCategory.OSINT
    api_type = ApiType.FREE
    requires_api_key = False
    api_key_names = ["serpapi", "google_api_key", "google_search_cx", "github_token"]
    result_types = ["social_profile", "url"]
    target_types = ["person"]

    async def run(self, target: str, config: dict = None) -> PluginResult:
        result = PluginResult(plugin_name=self.name, result_type="social_profile")
        config = config or {}
        deep_scan = config.get("deep_scan", False)

        try:
            from modules.osint import OSINTCollector
            collector = OSINTCollector(
                google_api_key=self.api_keys.get("google_api_key"),
                google_search_cx=self.api_keys.get("google_search_cx"),
                github_token=self.api_keys.get("github_token"),
            )

            # Primary: key-free multi-source discovery with confidence tiers.
            discovery = await collector.discover_person(target, deep_scan=deep_scan)
            profiles = discovery.get("profiles", [])
            summary = discovery.get("summary", {})

            # Optional enrichment when API keys are configured (extra recall).
            extra = []
            if collector.google_api_key and collector.google_search_cx:
                try:
                    extra.extend(await collector.search_google_custom_search(target))
                except Exception:
                    pass
            serp_api_key = self.api_keys.get("serpapi")
            if serp_api_key:
                try:
                    extra.extend(await collector.search_engine_profiles(target, api_key=serp_api_key))
                except Exception:
                    pass
            # Merge any API-sourced profiles that aren't already present.
            seen = {p.get("url", "").rstrip("/").lower() for p in profiles}
            for p in extra:
                key = (p.get("url") or "").rstrip("/").lower()
                if key and key not in seen:
                    seen.add(key)
                    p.setdefault("confidence", "Likely")
                    p.setdefault("match_quality", 70)
                    profiles.append(p)

            # Format for the UI (per_value_metadata alignment).
            final_values = []
            per_value_meta = []
            for p in profiles:
                platform = p.get("platform", "Web")
                url = p.get("url", "")
                title = p.get("title") or url
                snippet = p.get("snippet", "")

                final_values.append(f"{platform}: {title} ({url})")
                meta = {
                    "platform": platform,
                    "url": url,
                    "title": title,
                    "snippet": snippet,
                    "confidence": p.get("confidence", "Candidate"),
                    "match_quality": p.get("match_quality", 60),
                    "category": p.get("category", ""),
                }

                haystack = f"{title} {snippet}"
                emails = list(dict.fromkeys(_EMAIL_RE.findall(haystack)))
                phones = list(dict.fromkeys(_PHONE_RE.findall(haystack)))
                if emails:
                    meta["emails"] = emails
                if phones:
                    meta["phones"] = phones

                per_value_meta.append(meta)

            result.values = final_values
            result.per_value_metadata = per_value_meta
            result.metadata = {
                "summary": summary,
                "total_found": summary.get("total", len(profiles)),
                "confirmed": summary.get("confirmed", 0),
                "likely": summary.get("likely", 0),
                "candidate": summary.get("candidate", 0),
                "platforms": summary.get("platforms", 0),
                "sites_checked": summary.get("sites_checked", 0),
                "suggested_pivots": collector._extract_pivots(profiles),
                "deep_scan_enabled": deep_scan,
                "raw_dorks": self._get_raw_dorks(target),
            }

            if not profiles:
                result.metadata["note"] = (
                    "No public profiles matched. Try Deep Discovery mode, verify the "
                    "spelling, or add a Google CSE / SerpApi key for broader coverage."
                )

        except Exception as e:
            result.errors.append(str(e))
            result.success = False
        return result

    def _get_raw_dorks(self, name: str) -> list:
        import urllib.parse
        name_url = urllib.parse.quote(name)
        name_dash = name.lower().replace(" ", "-")
        name_plus = name.replace(" ", "+")
        return [
            f"FastPeopleSearch: https://www.fastpeoplesearch.com/name/{name_dash}",
            f"TruePeopleSearch: https://www.truepeoplesearch.com/results?name={name_url}",
            f"LinkedIn Dork: https://www.google.com/search?q=site:linkedin.com/in/+%22{name_plus}%22",
            f"Social Media Dork: https://www.google.com/search?q=%22{name_plus}%22+(site:twitter.com+OR+site:facebook.com)",
        ]
