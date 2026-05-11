"""
Active SMTP Email Validator Plugin.
Performs an SMTP handshake (MX lookup, HELO, MAIL FROM, RCPT TO) to verify email existence.
"""
from plugins.base import PluginBase, PluginResult, PluginCategory, ApiType

class ActiveEmailValidatorPlugin(PluginBase):
    name = "Active SMTP Email Validator"
    description = "Validates discovered emails using active SMTP handshakes to verify inbox existence."
    category = PluginCategory.INTERNAL # User requested it be categorized as active_recon. Internal handles active recon tasks here.
    api_type = ApiType.FREE
    requires_api_key = False
    result_types = ["verified_email"]
    target_types = ["email"]

    async def run(self, target: str, config: dict = None) -> PluginResult:
        result = PluginResult(plugin_name=self.name, result_type="verified_email")
        
        from modules.active_recon import ActiveRecon
        recon = ActiveRecon(timeout=10.0)
        
        # Check mode - Active recon should only run if mode allows it (ActiveRecon handles this logic ideally, but we verify here too)
        # RedSurface uses 'passive' / 'active' mode.
        mode = config.get("mode", "passive") if config else "passive"
        
        if mode != "active":
             result.values = [f"{target} (Skipped - Active Mode Required)"]
             result.metadata["status"] = "skipped_mode"
             return result

        validation = await recon.validate_email_smtp(target)
        
        is_valid = validation.get("is_valid", False)
        is_catchall = validation.get("is_catchall", False)
        reason = validation.get("reason", "Unknown")
        
        status_text = "Valid" if is_valid else "Invalid/Unverified"
        if is_catchall:
            status_text = "Catch-All (Unreliable)"
            
        result.values = [f"{target} - {status_text} ({reason})"]
        result.metadata = validation
        result.success = True
        
        return result
