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

    # Expanded curated platform checks
    PLATFORMS = {
        "GitHub": ("https://github.com/{}", 200, None),
        "Reddit": ("https://www.reddit.com/user/{}/about.json", 200, None),
        "Keybase": ("https://keybase.io/_/api/1.0/user/lookup.json?usernames={}", 200, '"status":{"code":0'),
        "HackerNews": ("https://hacker-news.firebaseio.com/v0/user/{}.json", 200, 'created'),
        "Linktree": ("https://linktr.ee/{}", 200, '<title>@{}'),
        "Steam": ("https://steamcommunity.com/id/{}", 200, 'steam_profile'),
        "Pastebin": ("https://pastebin.com/u/{}", 200, None),
        "Vimeo": ("https://vimeo.com/{}", 200, None),
        "Twitter": ("https://twitter.com/{}", 200, None),
        "Instagram": ("https://www.instagram.com/{}/", 200, None),
        "Facebook": ("https://www.facebook.com/{}", 200, None),
        "TikTok": ("https://www.tiktok.com/@{}", 200, None),
        "Medium": ("https://medium.com/@{}", 200, None),
        "Behance": ("https://www.behance.net/{}", 200, None),
        "Dribbble": ("https://dribbble.com/{}", 200, None),
        "GitLab": ("https://gitlab.com/{}", 200, None),
        "Bitbucket": ("https://bitbucket.org/{}/", 200, None),
        "Pinterest": ("https://www.pinterest.com/{}/", 200, None),
        "Quora": ("https://www.quora.com/profile/{}", 200, None),
        "Patreon": ("https://www.patreon.com/{}", 200, None),
        "About.me": ("https://about.me/{}", 200, None),
        "Disqus": ("https://disqus.com/by/{}/", 200, None),
        "Flickr": ("https://www.flickr.com/people/{}/", 200, None),
        "Goodreads": ("https://www.goodreads.com/{}", 200, None),
        "Instructables": ("https://www.instructables.com/member/{}/", 200, None),
        "Last.fm": ("https://www.last.fm/user/{}", 200, None),
        "Letterboxd": ("https://letterboxd.com/{}/", 200, None),
        "ProductHunt": ("https://www.producthunt.com/@{}", 200, None),
        "SoundCloud": ("https://soundcloud.com/{}", 200, None),
        "Spotify": ("https://open.spotify.com/user/{}", 200, None),
        "Twitch": ("https://www.twitch.tv/{}", 200, None),
        "Wattpad": ("https://www.wattpad.com/user/{}", 200, None),
        "YouTube": ("https://www.youtube.com/@{}", 200, None),
        "SlideShare": ("https://www.slideshare.net/{}", 200, None),
        "Scribd": ("https://www.scribd.com/{}", 200, None),
        "DeviantArt": ("https://www.deviantart.com/{}", 200, None),
        "Kaggle": ("https://www.kaggle.com/{}", 200, None),
        "Letterboxd": ("https://letterboxd.com/{}", 200, None),
        "OpenStreetMap": ("https://www.openstreetmap.org/user/{}", 200, None),
        "Telegram": ("https://t.me/{}", 200, None),
        "Substack": ("https://{}.substack.com", 200, None),
        "BuyMeACoffee": ("https://www.buymeacoffee.com/{}", 200, None),
        "Gumroad": ("https://{}.gumroad.com", 200, None),
        "InterPals": ("https://www.interpals.net/{}", 200, None),
        "Itch.io": ("https://{}.itch.io", 200, None),
        "Vsco": ("https://vsco.co/{}", 200, None),
    }

    async def run(self, target: str, config: dict = None) -> PluginResult:
        result = PluginResult(plugin_name=self.name, result_type="social_profile")
        username = target.strip()
        sem = asyncio.Semaphore(10) # Process 10 platforms at a time
        
        async def check_platform(client: httpx.AsyncClient, plat_name: str, settings: tuple):
            async with sem:
                url_tpl, expected_status, check_text = settings
                url = url_tpl.format(username)
                try:
                    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"}
                    resp = await client.get(url, headers=headers, follow_redirects=True, timeout=12.0)
                    
                    if resp.status_code == expected_status:
                        if check_text:
                            text_to_find = check_text.format(username) if "{}" in check_text else check_text
                            if text_to_find in resp.text:
                                # Found! Now enrich with metadata
                                meta = await collector.fetch_profile_metadata(url, plat_name)
                                return plat_name, url, meta
                        else:
                            # Avoid false positives
                            not_found_indicators = ["not found", "404", "doesn't exist", "doesn't live here", "page not found"]
                            if any(indicator in resp.text.lower()[:2000] for indicator in not_found_indicators):
                                return None, None, None
                                
                            if "reddit.com" in url_tpl:
                                try:
                                    data = resp.json()
                                    if "data" in data and not data.get("error"):
                                        return plat_name, url, {"title": f"Reddit: {username}", "description": "Reddit User Profile"}
                                except: pass
                            else:
                                # Found! Enrich with metadata
                                meta = await collector.fetch_profile_metadata(url, plat_name)
                                return plat_name, url, meta
                except Exception:
                    pass
                return None, None, None

        profiles_found = []
        from modules.osint import OSINTCollector
        collector = OSINTCollector()
        
        async with httpx.AsyncClient(verify=False) as client:
            tasks = []
            for name, settings in self.PLATFORMS.items():
                tasks.append(check_platform(client, name, settings))
            
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            enriched_profiles = []
            for resp in responses:
                if isinstance(resp, tuple) and resp[0]:
                    plat_name, url, meta = resp
                    display_title = meta.get("title") or plat_name
                    bio = meta.get("description") or "No bio available."
                    
                    profiles_found.append(f"{plat_name}: {display_title} ({url})")
                    enriched_profiles.append({
                        "platform": plat_name,
                        "url": url,
                        "title": display_title,
                        "snippet": bio,
                        "match_quality": 100 # Direct username match
                    })
            
            # Combine and sort to maintain alignment
            combined = sorted(zip(profiles_found, enriched_profiles), key=lambda x: x[0])
            
            if combined:
                result.values, result.per_value_metadata = map(list, zip(*combined))
            else:
                result.values = []
                result.per_value_metadata = []

            # Holehe-style active check (e.g. Twitter password recovery)
            if "@" in target:
                try:
                    tw_headers = {"User-Agent": "Mozilla/5.0"}
                    tw_resp = await client.post(
                        "https://api.twitter.com/i/users/email_available.json",
                        params={"email": target},
                        headers=tw_headers,
                        timeout=5.0
                    )
                    if tw_resp.status_code == 200:
                        data = tw_resp.json()
                        if not data.get("valid", True):
                            result.values.append(f"Twitter (Email Registered): {target}")
                            result.per_value_metadata.append({
                                "platform": "Twitter",
                                "url": f"https://twitter.com/i/users/email_available.json",
                                "title": "Twitter Registration Check",
                                "snippet": "Target email is registered on Twitter.",
                                "match_quality": 100
                            })
                except Exception:
                    pass

        result.metadata = {"total_found": len(result.values)}
        return result
