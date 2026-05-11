"""
PGP Key Server Search — Find email addresses from PGP public key servers.
"""
from plugins.base import PluginBase, PluginResult, PluginCategory, ApiType


class PGPSearchPlugin(PluginBase):
    name = "PGP Key Server Search"
    description = "Find email addresses of technical staff from PGP public key servers."
    category = PluginCategory.OSINT
    api_type = ApiType.FREE
    requires_api_key = False
    result_types = ["email", "person"]
    target_types = ["domain", "email", "person"]

    async def run(self, target: str, config: dict = None) -> PluginResult:
        result = PluginResult(plugin_name=self.name, result_type="email")
        try:
            from modules.osint import OSINTCollector
            collector = OSINTCollector(timeout=(config or {}).get("timeout", 15.0))
            people = await collector.search_pgp(target)
            result.values = sorted(set(p.email for p in people if p.email))
            result.metadata = {
                "people": [p.to_dict() for p in people],
            }
        except Exception as e:
            result.errors.append(str(e))
            result.success = False
        return result
