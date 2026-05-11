"""
ViewDNS Reverse WHOIS Plugin — Finds other domains owned by the same person/company.
"""
from plugins.base import PluginBase, PluginResult, PluginCategory, ApiType

class ViewDNSPlugin(PluginBase):
    name = "ViewDNS Reverse WHOIS"
    description = "Finds other domains owned by the same registrant email or company."
    category = PluginCategory.OSINT
    api_type = ApiType.FREE
    requires_api_key = False
    result_types = ["domain"]
    target_types = ["domain", "email"]

    async def run(self, target: str, config: dict = None) -> PluginResult:
        result = PluginResult(plugin_name=self.name, result_type="domain")
        
        from modules.osint import OSINTCollector
        collector = OSINTCollector()
        
        domains = await collector.search_viewdns(target)
        
        for d in domains:
            result.values.append(d.get("domain", ""))
            
        result.metadata = {"domains_found": domains}
        result.success = True
        
        return result
