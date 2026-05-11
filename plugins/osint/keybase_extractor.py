"""
Keybase Profile Extractor Plugin
"""
import httpx
from plugins.base import PluginBase, PluginResult, PluginCategory, ApiType


class KeybaseExtractorPlugin(PluginBase):
    name = "Keybase Profile Extractor"
    description = "Pulls cryptographic proofs and linked identities (Twitter, Github, Domains) directly from Keybase records."
    category = PluginCategory.OSINT
    api_type = ApiType.FREE
    requires_api_key = False
    result_types = ["social_profile", "domain"]
    target_types = ["username"]

    async def run(self, target: str, config: dict = None) -> PluginResult:
        result = PluginResult(plugin_name=self.name, result_type="social_profile")
        username = target.strip()
        
        url = f"https://keybase.io/_/api/1.0/user/lookup.json?usernames={username}"
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) RedSurface"}

        try:
            async with httpx.AsyncClient(verify=False) as client:
                resp = await client.get(url, headers=headers, timeout=15.0)

                if resp.status_code == 200:
                    data = resp.json()
                    status = data.get("status", {})
                    
                    if status.get("code") == 0:
                        them = data.get("them", [])
                        if them and isinstance(them[0], dict):
                            user_data = them[0]
                            proofs = user_data.get("proofs_summary", {}).get("all", [])
                            
                            found = []
                            for proof in proofs:
                                p_type = proof.get("proof_type")
                                p_name = proof.get("nametag")
                                p_url = proof.get("service_url")
                                found.append(f"{p_type.capitalize()}: {p_name} ({p_url})")
                                
                            if not found:
                                found.append("Account exists but has no public proofs.")
                                
                            result.values = found
                        else:
                            result.values = []
                    else:
                        result.values = []
                else:
                    result.errors.append(f"Keybase API returned status {resp.status_code}")
                    result.success = False

        except Exception as e:
            result.errors.append(str(e))
            result.success = False

        return result
