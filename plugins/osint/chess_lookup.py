"""
Chess.com Profile info Plugin
"""
import httpx
from plugins.base import PluginBase, PluginResult, PluginCategory, ApiType

class ChessLookupPlugin(PluginBase):
    name = "Chess.com Profile Lookup"
    description = "Fetches the player's real name, location, and social links from their open profile on Chess.com."
    category = PluginCategory.OSINT
    api_type = ApiType.FREE
    requires_api_key = False
    result_types = ["person", "social_profile"]
    target_types = ["username"]

    async def run(self, target: str, config: dict = None) -> PluginResult:
        result = PluginResult(plugin_name=self.name, result_type="person")
        username = target.strip()
        
        url = f"https://api.chess.com/pub/player/{username}"
        headers = {"User-Agent": "Mozilla/5.0 - RedSurface OSINT Plugin"}

        try:
            async with httpx.AsyncClient(verify=False) as client:
                resp = await client.get(url, headers=headers, timeout=15.0)

                if resp.status_code == 200:
                    data = resp.json()
                    
                    found = []
                    
                    name = data.get("name")
                    if name:
                        found.append(f"Real Name: {name}")
                        
                    location = data.get("location")
                    if location:
                        found.append(f"Location: {location}")
                        
                    country = data.get("country")
                    if country:
                        found.append(f"Country ID url: {country}")

                    twitch = data.get("twitch_url")
                    if twitch:
                        found.append(f"Twitch: {twitch}")
                        
                    is_streamer = data.get("is_streamer", False)
                    if is_streamer:
                        found.append("Is a registered streamer")

                    if not found:
                        found.append("Profile exists but fields (Name, Location) are empty.")
                        
                    result.values = found
                elif resp.status_code == 404:
                    result.values = []
                else:
                    result.errors.append(f"Chess.com returned status {resp.status_code}")
                    result.success = False

        except Exception as e:
            result.errors.append(str(e))
            result.success = False

        return result
