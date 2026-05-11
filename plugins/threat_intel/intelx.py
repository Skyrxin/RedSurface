"""
IntelX Plugin — Searches Intelligence X for leaked data.
"""
from plugins.base import PluginBase, PluginResult, PluginCategory, ApiType

class IntelXPlugin(PluginBase):
    name = "Intelligence X"
    description = "Searches Intelligence X for leaked data associated with the target domain or email."
    category = PluginCategory.THREAT_INTEL # Fits better in Threat Intel for leaks
    api_type = ApiType.PAID
    requires_api_key = False
    api_key_names = ["intelx"]
    result_types = ["leak"]
    target_types = ["domain", "email"]

    async def run(self, target: str, config: dict = None) -> PluginResult:
        result = PluginResult(plugin_name=self.name, result_type="leak")
        
        from modules.osint import OSINTCollector
        collector = OSINTCollector()
        
        api_key = self.api_keys.get("intelx")
        leaks = await collector.search_intelx(target, api_key=api_key)
        
        for leak in leaks:
            result.values.append(leak)
            
        if not api_key:
            result.values.append("Warning: IntelX API key not configured. Cannot search for leaks.")
            
        result.metadata = {"total_leaks": len(leaks)}
        result.success = True
        
        return result
