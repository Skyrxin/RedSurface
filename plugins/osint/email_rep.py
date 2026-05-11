"""
EmailRep Plugin — Analyzes an email address for reputation and open-source footprints.
"""
import httpx
from plugins.base import PluginBase, PluginResult, PluginCategory, ApiType


class EmailRepPlugin(PluginBase):
    name = "EmailRep.io Analysis"
    description = "Check email reputation, data breaches, and linked social profiles."
    category = PluginCategory.OSINT
    api_type = ApiType.FREE
    requires_api_key = False
    result_types = ["email_intel"]
    target_types = ["email"]
    website = "https://emailrep.io/"

    async def run(self, target: str, config: dict = None) -> PluginResult:
        result = PluginResult(plugin_name=self.name, result_type="email_intel")
        email = target.strip().lower()

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(f"https://emailrep.io/{email}", headers={"User-Agent": "RedSurface/2.0"})
                
                if resp.status_code == 200:
                    data = resp.json()
                    details = data.get("details", {})
                    
                    rep = data.get("reputation", "none")
                    suspicious = data.get("suspicious", False)
                    leaked = details.get("credentials_leaked", False)
                    profiles = details.get("profiles", [])

                    findings = []
                    findings.append(f"Reputation: {rep.upper()}")
                    findings.append(f"Suspicious: {'Yes' if suspicious else 'No'}")
                    findings.append(f"Credentials Leaked: {'Yes (Appears in breaches)' if leaked else 'No'}")
                    
                    if profiles:
                        findings.append(f"Linked Profiles on: {', '.join(profiles)}")

                    if details.get("blacklisted"):
                        findings.append("Warning: Email is explicitly blacklisted.")
                        
                    result.values = findings
                    result.metadata = data
                elif resp.status_code == 429:
                    result.errors.append("EmailRep.io rate limit exceeded. Try again later.")
                    result.success = False
                else:
                    result.errors.append(f"API returned {resp.status_code}")
                    result.success = False
        except Exception as e:
            result.errors.append(f"Connection error: {str(e)}")
            result.success = False

        return result
