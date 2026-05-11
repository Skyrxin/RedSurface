"""
Gravatar Profile Lookup Plugin
"""
import hashlib
import httpx
from plugins.base import PluginBase, PluginResult, PluginCategory, ApiType


class GravatarLookupPlugin(PluginBase):
    name = "Gravatar Profile Lookup"
    description = "Retrieves associated usernames, display names, and linked URLs from a globally recognized avatar hash."
    category = PluginCategory.OSINT
    api_type = ApiType.FREE
    requires_api_key = False
    result_types = ["social_profile"]
    target_types = ["email"]

    async def run(self, target: str, config: dict = None) -> PluginResult:
        result = PluginResult(plugin_name=self.name, result_type="social_profile")
        email = target.strip().lower()
        email_hash = hashlib.md5(email.encode("utf-8")).hexdigest()

        try:
            url = f"https://en.gravatar.com/{email_hash}.json"
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) RedSurface"}
            
            async with httpx.AsyncClient(verify=False) as client:
                resp = await client.get(url, headers=headers, timeout=15.0)

                if resp.status_code == 200:
                    data = resp.json()
                    entry = data.get("entry", [])[0]
                    
                    found_data = []
                    
                    display_name = entry.get("displayName")
                    if display_name:
                        found_data.append(f"Name: {display_name}")
                        
                    profile_url = entry.get("profileUrl")
                    if profile_url:
                        found_data.append(f"Profile: {profile_url}")
                        
                    about = entry.get("aboutMe")
                    if about:
                        found_data.append(f"Bio: {about}")
                        
                    for acc in entry.get("accounts", []):
                        found_data.append(f"Linked Account: {acc.get('domain', 'Unknown')} ({acc.get('username', '')})")
                        
                    for url_obj in entry.get("urls", []):
                        found_data.append(f"Website: {url_obj.get('value')} ({url_obj.get('title')})")

                    result.values = found_data
                    result.metadata = {"hash": email_hash}
                elif resp.status_code == 404:
                    result.values = ["No Gravatar profile found."]
                else:
                    result.errors.append(f"Gravatar returned status {resp.status_code}")
                    result.success = False

        except Exception as e:
            result.errors.append(str(e))
            result.success = False
            
        return result
