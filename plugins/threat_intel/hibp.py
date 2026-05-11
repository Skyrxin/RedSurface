"""
Have I Been Pwned Plugin — Check for breached email accounts from a domain.
Requires HIBP API key ($3.50/month).
"""
from plugins.base import PluginBase, PluginResult, PluginCategory, ApiType


class HIBPPlugin(PluginBase):
    name = "Have I Been Pwned"
    description = (
        "Check if email addresses from a domain appear in known data breaches. "
        "Requires a paid HIBP API key ($3.50/month)."
    )
    category = PluginCategory.THREAT_INTEL
    api_type = ApiType.TIERED
    requires_api_key = True
    api_key_names = ["HIBP_KEY"]
    result_types = ["breach"]
    target_types = ["domain", "email"]
    website = "https://haveibeenpwned.com/"

    async def run(self, target: str, config: dict = None) -> PluginResult:
        result = PluginResult(plugin_name=self.name, result_type="breach")
        try:
            from modules.osint import OSINTCollector

            collector = OSINTCollector()
            
            target_type = config.get("target_type", "domain") if config else "domain"
            
            if target_type == "email":
                breached = await collector.search_hibp_email(
                    email=target,
                    api_key=self.api_keys.get("HIBP_KEY"),
                )
            else:
                breached = await collector.search_hibp(
                    domain=target,
                    api_key=self.api_keys.get("HIBP_KEY"),
                )

            result.values = sorted(set(breached))
            result.metadata = {
                "total_breached": len(breached),
            }
        except Exception as e:
            result.errors.append(str(e))
            result.success = False
        return result
