"""
DNS Brute-forcer — Subdomain discovery via wordlist-based DNS resolution.
"""
from plugins.base import PluginBase, PluginResult, PluginCategory, ApiType


class DNSBrutePlugin(PluginBase):
    name = "DNS Brute-forcer"
    description = "Discover subdomains by brute-forcing common names via DNS resolution."
    category = PluginCategory.DISCOVERY
    api_type = ApiType.INTERNAL
    requires_api_key = False
    result_types = ["subdomain"]

    async def run(self, target: str, config: dict = None) -> PluginResult:
        result = PluginResult(plugin_name=self.name, result_type="subdomain")
        try:
            from modules.discovery import InfrastructureDiscoverer
            d = InfrastructureDiscoverer(
                use_crtsh=False,
                analyze_ssl=False,
                max_concurrent=(config or {}).get("max_concurrent", 30),
            )
            # Only run the wordlist enumeration + DNS resolution phase
            import asyncio
            alive = []
            semaphore = asyncio.Semaphore(d.max_concurrent)
            for sub in d.wordlist:
                hostname = f"{sub}.{target}"

                async def resolve(h=hostname):
                    async with semaphore:
                        asset = await d.resolve_dns(h)
                        if asset.is_alive:
                            return h
                        return None

                alive.append(resolve())
            results = await asyncio.gather(*alive, return_exceptions=True)
            result.values = sorted([r for r in results if isinstance(r, str)])
        except Exception as e:
            result.errors.append(str(e))
            result.success = False
        return result
