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
    api_key_names = ["serpapi"]
    result_types = ["social_profile", "url"]
    target_types = ["person"]

    async def run(self, target: str, config: dict = None) -> PluginResult:
        result = PluginResult(plugin_name=self.name, result_type="social_profile")
        config = config or {}
        deep_scan = config.get("deep_scan", False)

        try:
            from modules.osint import OSINTCollector
            collector = OSINTCollector()
            
            # Perform actual web search using SerpApi
            api_key = self.api_keys.get("serpapi")
            profiles = await collector.search_engine_profiles(target, api_key=api_key)
            
            pivots = [] # Adjusting pivot extraction since we use a different dict structure now
            
            # Format results for the UI
            formatted_results = []
            for p in profiles:
                formatted_results.append(f"{p['platform']}: {p['title']} ({p['url']})")
                
            if not profiles and collector._check_loop_prevention(target, "person_web_profiles"):
                result.metadata["loop_prevention"] = True
                result.values = ["Notice: Scan skipped to prevent redundant looping. Try again in 5 minutes if needed."]
            else:
                result.values = formatted_results
            
            if not api_key:
                result.values.append("Warning: SerpApi key not configured. Only raw dorks are available.")
            
            result.metadata = {
                "profiles": profiles,
                "total_found": len(profiles),
                "suggested_pivots": pivots,
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
