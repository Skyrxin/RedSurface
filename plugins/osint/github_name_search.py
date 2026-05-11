"""
GitHub Name Search Plugin — Finds developers matching a full name.
"""
from plugins.base import PluginBase, PluginResult, PluginCategory, ApiType


class GithubNameSearchPlugin(PluginBase):
    name = "GitHub Name Search"
    description = "Searches the official GitHub API to find user profiles with names matching the target identity."
    category = PluginCategory.OSINT
    api_type = ApiType.FREE
    requires_api_key = False
    result_types = ["social_profile", "person"]
    target_types = ["person"]

    async def run(self, target: str, config: dict = None) -> PluginResult:
        result = PluginResult(plugin_name=self.name, result_type="social_profile")
        try:
            from modules.osint import OSINTCollector
            collector = OSINTCollector()
            
            # API query
            profiles = await collector.search_github_by_name(target)
            
            formatted = []
            for p in profiles:
                formatted.append(f"{p['title']} ({p['url']})")
                
            result.values = formatted
            result.metadata = {
                "profiles": profiles,
                "total_found": len(profiles)
            }
            
        except Exception as e:
            result.errors.append(str(e))
            result.success = False
        return result
