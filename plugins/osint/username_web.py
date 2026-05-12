"""
Username Web Discovery Plugin — Searches the open web for exact username mentions.
Goes beyond the hardcoded platform list to find obscure forums, pastes, and personal sites.
"""
from plugins.base import PluginBase, PluginResult, PluginCategory, ApiType


class UsernameWebDiscoveryPlugin(PluginBase):
    name = "Username Web Discovery"
    description = "Searches Google, DuckDuckGo, and Bing for exact username mentions and enriches discovered URLs."
    category = PluginCategory.OSINT
    api_type = ApiType.PAID
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
                google_search_cx=self.api_keys.get("google_search_cx")
            )
            
            all_discovered = []
            
            # 1. Search Open Web using exact username query
            # We use double quotes for exact match in dorks
            
            # Use Google CSE if available (Raw Query Mode)
            if collector.google_api_key and collector.google_search_cx:
                cse_results = await collector.search_google_custom_search(f'"{username}"', is_raw_query=True)
                all_discovered.extend(cse_results)
            
            # Use broad web scraping (DDG / Google Broad)
            web_results = await collector.search_web_broad(f'"{username}"')
            all_discovered.extend(web_results)
            
            # De-duplicate by URL
            unique_links = []
            seen_urls = set()
            for p in all_discovered:
                norm_url = p['url'].rstrip('/').lower()
                if norm_url not in seen_urls:
                    unique_links.append(p)
                    seen_urls.add(norm_url)
            
            # 2. Enrich discovered links using OG Tag Parser (Smart OSINT)
            final_profiles = []
            final_values = []
            per_value_meta = []
            
            for p in unique_links[:15]: # Limit enrichment to first 15 for speed
                # Fetch deeper metadata
                enriched_meta = await collector.fetch_profile_metadata(p['url'], p['platform'])
                
                title = enriched_meta.get("title") or p['title']
                snippet = enriched_meta.get("description") or p.get("snippet", "No description available.")
                
                final_values.append(f"{p['platform']}: {title} ({p['url']})")
                per_value_meta.append({
                    "platform": p['platform'],
                    "url": p['url'],
                    "title": title,
                    "snippet": snippet,
                    "match_quality": p.get('match_quality', 80)
                })

            result.values = final_values
            result.per_value_metadata = per_value_meta
            
            result.metadata = {
                "total_found": len(final_values),
                "deep_scan_enabled": deep_scan
            }
            
            if not (collector.google_api_key and collector.google_search_cx):
                result.values.append("Note: Google CSE not configured. Searching via fallback scrapers.")
            
        except Exception as e:
            result.errors.append(str(e))
            result.success = False
        return result
