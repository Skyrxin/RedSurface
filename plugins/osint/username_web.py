"""
Username Web Discovery Plugin — Searches the open web for exact username mentions.
Goes beyond the hardcoded platform list to find obscure forums, pastes, and personal sites.
"""
from plugins.base import PluginBase, PluginResult, PluginCategory, ApiType


class UsernameWebDiscoveryPlugin(PluginBase):
    name = "Username Web Discovery"
    description = "Searches the open web (DuckDuckGo + Bing) for exact username mentions on forums, pastes, and personal sites."
    category = PluginCategory.OSINT
    api_type = ApiType.FREE
    requires_api_key = False
    api_key_names = ["google_api_key", "google_search_cx"]
    result_types = ["social_profile", "url"]
    target_types = ["username"]

    async def run(self, target: str, config: dict = None) -> PluginResult:
        result = PluginResult(plugin_name=self.name, result_type="social_profile")
        config = config or {}
        deep_scan = config.get("deep_scan", False)
        username = target.strip()

        try:
            from modules.osint import OSINTCollector
            collector = OSINTCollector(
                google_api_key=self.api_keys.get("google_api_key"),
                google_search_cx=self.api_keys.get("google_search_cx"),
            )

            all_discovered = []

            # Google CSE first (raw query) when keys are present.
            if collector.google_api_key and collector.google_search_cx:
                try:
                    all_discovered.extend(
                        await collector.search_google_custom_search(f'"{username}"', is_raw_query=True)
                    )
                except Exception:
                    pass

            # Resilient multi-engine web search (DuckDuckGo + Bing).
            for raw in await collector.web_search(f'"{username}"', max_results=25):
                url = raw.get("url", "")
                all_discovered.append({
                    "url": url,
                    "title": raw.get("title", ""),
                    "platform": collector._classify_platform(url),
                })

            # De-duplicate by URL, keep only results that actually mention the handle.
            unique_links = []
            seen_urls = set()
            for p in all_discovered:
                norm_url = (p.get("url") or "").rstrip("/").lower()
                if not norm_url or norm_url in seen_urls:
                    continue
                if username.lower() not in norm_url and username.lower() not in (p.get("title", "").lower()):
                    continue
                seen_urls.add(norm_url)
                unique_links.append(p)

            # Enrich discovered links using the OG-tag parser.
            final_values = []
            per_value_meta = []
            for p in unique_links[:15]:
                enriched = await collector.fetch_profile_metadata(p["url"], p.get("platform", "Web"))
                title = enriched.get("title") or p.get("title") or p["url"]
                snippet = enriched.get("description") or "Username mention found on the open web."
                platform = p.get("platform", "Web")

                final_values.append(f"{platform}: {title} ({p['url']})")
                per_value_meta.append({
                    "platform": platform,
                    "url": p["url"],
                    "title": title,
                    "snippet": snippet,
                    "confidence": "Likely" if platform != "Web" else "Candidate",
                    "match_quality": 75 if platform != "Web" else 55,
                    "category": "",
                })

            result.values = final_values
            result.per_value_metadata = per_value_meta
            result.metadata = {
                "total_found": len(final_values),
                "deep_scan_enabled": deep_scan,
                "engines": "duckduckgo+bing",
            }

        except Exception as e:
            result.errors.append(str(e))
            result.success = False
        return result
