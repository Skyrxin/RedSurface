"""
Username Enumeration Plugin — Checks popular platforms for username existence.
"""
import asyncio
import httpx
from plugins.base import PluginBase, PluginResult, PluginCategory, ApiType


class UsernameEnumPlugin(PluginBase):
    name = "Cross-Platform Username Enum"
    description = "Check if a username exists across major platforms (GitHub, Twitter, Reddit, etc)."
    category = PluginCategory.OSINT
    api_type = ApiType.FREE
    requires_api_key = False
    result_types = ["social_profile"]
    target_types = ["username"]
    website = ""

    # Platform checks: format is {name: (url_template, expect_status, check_text_in_body)}
    PLATFORMS = {
        "GitHub": ("https://github.com/{}", 200, None),
        "Reddit": ("https://www.reddit.com/user/{}/about.json", 200, None),
        "Keybase": ("https://keybase.io/_/api/1.0/user/lookup.json?usernames={}", 200, '"status":{"code":0'),
        "HackerNews": ("https://hacker-news.firebaseio.com/v0/user/{}.json", 200, 'created'),
        "Linktree": ("https://linktr.ee/{}", 200, '<title>@{}'),
        "Steam": ("https://steamcommunity.com/id/{}", 200, 'steam_profile'),
        "Pastebin": ("https://pastebin.com/u/{}", 200, None),
        "Vimeo": ("https://vimeo.com/{}", 200, None),
    }

    async def run(self, target: str, config: dict = None) -> PluginResult:
        result = PluginResult(plugin_name=self.name, result_type="social_profile")
        username = target.strip()
        
        async def check_platform(client: httpx.AsyncClient, plat_name: str, settings: tuple):
            url_tpl, expected_status, check_text = settings
            url = url_tpl.format(username)
            try:
                # Use browser-like headers to avoid blocking
                headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/110.0.0.0 Safari/537.36"}
                resp = await client.get(url, headers=headers, follow_redirects=True, timeout=15.0)
                
                if resp.status_code == expected_status:
                    if check_text:
                        # Sometimes we need to format the check text (e.g. for Linktree)
                        text_to_find = check_text.format(username) if "{}" in check_text else check_text
                        if text_to_find in resp.text:
                            return plat_name, url
                    else:
                        # For Reddit json check
                        if "reddit.com" in url_tpl:
                            data = resp.json()
                            if "data" in data and not data.get("error"):
                                return plat_name, url
                        else:
                            return plat_name, url
            except Exception:
                pass
            return None, None

        profiles_found = []
        async with httpx.AsyncClient(verify=False) as client:
            tasks = []
            for name, settings in self.PLATFORMS.items():
                tasks.append(check_platform(client, name, settings))
            
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            for resp in responses:
                if isinstance(resp, tuple) and resp[0]:
                    plat_name, url = resp
                    profiles_found.append(f"{plat_name}: {url}")
            
            # Holehe-style active check (e.g. Twitter password recovery)
            if "@" in target:
                try:
                    # Very basic simulation of a recovery endpoint check
                    # Real implementations often require dealing with CSRF tokens and specific headers
                    tw_headers = {"User-Agent": "Mozilla/5.0"}
                    tw_resp = await client.post(
                        "https://api.twitter.com/i/users/email_available.json",
                        params={"email": target},
                        headers=tw_headers,
                        timeout=5.0
                    )
                    if tw_resp.status_code == 200:
                        data = tw_resp.json()
                        # If valid is false and msg says 'Email has already been taken', it exists
                        if not data.get("valid", True):
                            profiles_found.append(f"Twitter (Email Registered): {target}")
                except Exception:
                    pass

        result.values = sorted(profiles_found)
        result.metadata = {"total_found": len(profiles_found)}
        return result
