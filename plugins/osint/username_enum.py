"""
Username Enumeration Plugin — Checks a username across ~600 platforms.

Powered by the WhatsMyName dataset (vendored at data/wmn-data.json) via the shared
SocialEnumerator engine. Because it queries each platform directly using that
platform's own existence-detection rule, it is fast, high-yield, and does not
rate-limit the way search-engine scraping does.
"""
from plugins.base import PluginBase, PluginResult, PluginCategory, ApiType


class UsernameEnumPlugin(PluginBase):
    name = "Cross-Platform Username Enum"
    description = "Check if a username exists across ~600 platforms (GitHub, Reddit, Instagram, and hundreds more)."
    category = PluginCategory.OSINT
    api_type = ApiType.FREE
    requires_api_key = False
    result_types = ["social_profile"]
    target_types = ["username"]
    website = "https://github.com/WebBreacher/WhatsMyName"

    async def run(self, target: str, config: dict = None) -> PluginResult:
        result = PluginResult(plugin_name=self.name, result_type="social_profile")
        config = config or {}
        deep_scan = config.get("deep_scan", False)
        username = target.strip()

        try:
            from modules.social_enum import SocialEnumerator
            enumerator = SocialEnumerator()  # fast defaults: concurrency 100, retry on blips
            sites = enumerator.load_sites(include_protected=deep_scan, include_nsfw=deep_scan)

            hits = await enumerator.check_username(username, sites=sites)
            stats = enumerator.last_stats

            # Sort: high-signal identity categories first, then alphabetical.
            priority = {"social": 0, "coding": 1, "business": 2, "dating": 3}
            hits.sort(key=lambda h: (priority.get(h.get("category", ""), 9), h["platform"].lower()))

            final_values = []
            per_value_meta = []
            for h in hits:
                platform = h["platform"]
                url = h["url"]
                final_values.append(f"{platform}: @{username} ({url})")
                per_value_meta.append({
                    "platform": platform,
                    "url": url,
                    "title": f"{platform}: @{username}",
                    "snippet": f"Account exists on {platform} ({h.get('category', 'site')}).",
                    "confidence": "Confirmed",
                    "match_quality": 95,
                    "category": h.get("category", ""),
                })

            result.values = final_values
            result.per_value_metadata = per_value_meta
            result.metadata = {
                "total_found": len(hits),
                "confirmed": len(hits),
                "likely": 0,
                "candidate": 0,
                "platforms": len(hits),
                "sites_checked": len(sites),
                "sites_errored": stats.get("errored", 0),
                "coverage_pct": round(100 * (stats.get("checked", 0) - stats.get("errored", 0))
                                      / max(1, len(sites))),
                "deep_scan_enabled": deep_scan,
            }
            errored = stats.get("errored", 0)
            if not hits:
                result.metadata["note"] = (
                    f"'{username}' was not found on any of the {len(sites)} sites checked. "
                    "Try Deep Discovery mode to also scan captcha/NSFW-protected sites."
                )
            elif errored > len(sites) * 0.25:
                # Be honest when a chunk of the catalogue was unreachable (throttling
                # or transient outages) — a re-scan fills the gaps from cache-recovery.
                result.metadata["note"] = (
                    f"{errored} of {len(sites)} sites were unreachable this run "
                    f"(~{result.metadata['coverage_pct']}% coverage). Re-run to recover "
                    "them — confirmed hits and failed sites are not cached as absent."
                )

        except Exception as e:
            result.errors.append(str(e))
            result.success = False
        return result
