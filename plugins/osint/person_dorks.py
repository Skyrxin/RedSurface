"""
Web Profile Discovery Plugin — Automates finding actual social profiles for a name.
"""
from plugins.base import PluginBase, PluginResult, PluginCategory, ApiType


class WebProfileDiscoveryPlugin(PluginBase):
    name = "Web Profile Discovery"
    description = "Automatically searches the surface web for LinkedIn, Twitter, and other social profiles related to a name."
    category = PluginCategory.OSINT
    api_type = ApiType.PAID
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
                github_token=self.api_keys.get("github_token")
            )
            
            all_profiles = []
            
            # 1. Google Custom Search (Highly Reliable)
            if collector.google_api_key and collector.google_search_cx:
                cse_profiles = await collector.search_google_custom_search(target)
                all_profiles.extend(cse_profiles)
            
            # 2. SerpApi (if available)
            serp_api_key = self.api_keys.get("serpapi")
            if serp_api_key:
                serp_profiles = await collector.search_engine_profiles(target, api_key=serp_api_key)
                all_profiles.extend(serp_profiles)
            
            # 3. Enhanced Web Scraping Fallback
            web_profiles = await collector.search_web_profiles(target, deep_scan=deep_scan)
            all_profiles.extend(web_profiles)
            
            # 4. GitHub Name Search
            github_profiles = await collector.search_github_by_name(target)
            all_profiles.extend(github_profiles)
            
            # De-duplicate by URL
            unique_profiles = []
            seen_urls = set()
            for p in all_profiles:
                norm_url = p['url'].rstrip('/').lower()
                if norm_url not in seen_urls:
                    unique_profiles.append(p)
                    seen_urls.add(norm_url)
            
            # Format results for the UI using per_value_metadata (Smart OSINT Alignment)
            final_values = []
            per_value_meta = []
            
            for p in unique_profiles:
                final_values.append(f"{p['platform']}: {p['title']} ({p['url']})")
                per_value_meta.append({
                    "platform": p.get('platform', 'Web'),
                    "url": p.get('url', ''),
                    "title": p.get('title', ''),
                    "snippet": p.get('snippet', ''),
                    "match_quality": p.get('match_quality', 80)
                })

            if not unique_profiles and collector._check_loop_prevention(target, "person_web_profiles"):
                result.metadata["loop_prevention"] = True
                result.values = ["Notice: Scan skipped to prevent redundant looping. Try again in 5 minutes if needed."]
                result.per_value_metadata = [{}]
            else:
                result.values = final_values
                result.per_value_metadata = per_value_meta
            
            if not (serp_api_key or (collector.google_api_key and collector.google_search_cx)):
                result.values.append("Warning: No Search API keys (SerpApi or Google CSE) configured. Results rely on fallback scrapers.")
                result.per_value_metadata.append({}) # Keep lists aligned
            
            result.metadata = {
                "total_found": len(unique_profiles),
                "suggested_pivots": collector._extract_pivots(unique_profiles),
                "deep_scan_enabled": deep_scan,
                "raw_dorks": self._get_raw_dorks(target)
            }
            
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
            f"Social Media Dork: https://www.google.com/search?q=%22{name_plus}%22+(site:twitter.com+OR+site:facebook.com)"
        ]
