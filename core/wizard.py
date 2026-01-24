"""
Interactive Wizard for RedSurface.

Provides a user-friendly interactive mode for configuring and running scans.
Uses questionary for beautiful CLI prompts.
"""

import sys
from pathlib import Path
from typing import Optional, List, Tuple

try:
    import questionary
    from questionary import Style
    HAS_QUESTIONARY = True
    
    # Custom style for questionary prompts
    WIZARD_STYLE = Style([
        ("qmark", "fg:cyan bold"),
        ("question", "fg:white bold"),
        ("answer", "fg:green bold"),
        ("pointer", "fg:cyan bold"),
        ("highlighted", "fg:cyan bold"),
        ("selected", "fg:green"),
        ("separator", "fg:gray"),
        ("instruction", "fg:gray italic"),
        ("text", "fg:white"),
    ])
except ImportError:
    HAS_QUESTIONARY = False
    WIZARD_STYLE = None

from core.config import ScanConfig, ScanMode
from core.target import Target
from utils.logger import get_logger


class InteractiveWizard:
    """
    Interactive wizard for configuring RedSurface scans.
    
    Guides users through scan configuration with friendly prompts.
    """
    
    def __init__(self):
        """Initialize the interactive wizard."""
        self.logger = get_logger()
        self.config: Optional[ScanConfig] = None
        self.targets: List[Target] = []
        
        if not HAS_QUESTIONARY:
            self.logger.error("questionary library required for interactive mode")
            self.logger.error("Install with: pip install questionary")
    
    def _check_questionary(self) -> bool:
        """Check if questionary is available."""
        if not HAS_QUESTIONARY:
            print("\n[!] Interactive mode requires 'questionary' library.")
            print("    Install with: pip install questionary\n")
            return False
        return True
    
    def start(self) -> Tuple[Optional[ScanConfig], List[Target]]:
        """
        Start the interactive wizard.
        
        Guides the user through:
        1. Scan mode selection (Passive/Active)
        2. Target selection (Single/File)
        3. Custom wordlists (if Active mode)
        4. Scope filtering (exclusions)
        5. API keys (Shodan, etc.)
        
        Returns:
            Tuple of (ScanConfig, List[Target]) or (None, []) if cancelled
        """
        if not self._check_questionary():
            return None, []
        
        print("\n" + "=" * 60)
        print("  🔴 RedSurface Interactive Wizard")
        print("=" * 60 + "\n")
        
        try:
            # Step 1: Scan Mode Selection
            scan_mode = self._select_scan_mode()
            if scan_mode is None:
                return None, []
            
            # Step 2: Custom Module Selection (if Custom mode)
            module_selection = {}
            if scan_mode == ScanMode.CUSTOM:
                module_selection = self._select_modules()
                if module_selection is None:
                    return None, []
            
            # Step 2b: Phishing Configuration (if Phishing mode OR Custom mode with phishing selected)
            phishing_config = {}
            if scan_mode == ScanMode.PHISHING or module_selection.get("module_phishing", False):
                phishing_config = self._configure_phishing()
                if phishing_config is None:
                    # If phishing config cancelled but in Custom mode, just disable phishing
                    if scan_mode == ScanMode.CUSTOM:
                        module_selection["module_phishing"] = False
                        print("  ○ Phishing disabled (authorization not confirmed)\n")
                    else:
                        return None, []
            
            # Step 3: Target Selection
            targets = self._select_targets()
            if not targets:
                return None, []
            
            # Step 4: Custom Wordlists (only for Active/Custom mode with dir enum)
            wordlist_dirs = None
            wordlist_subs = None
            if scan_mode == ScanMode.ACTIVE or module_selection.get("module_dir_enum", False):
                wordlist_dirs = self._get_directory_wordlist()
                wordlist_subs = self._get_subdomain_wordlist()
            
            # Step 5: Scope Filtering
            scope_blacklist = self._get_scope_exclusions()
            
            # Step 6: API Keys (only ask for relevant ones based on mode/modules)
            shodan_key = None
            hunter_key = None
            nvd_key = None
            github_token = None
            hibp_key = None
            
            if scan_mode not in (ScanMode.CUSTOM, ScanMode.PHISHING) or module_selection.get("module_port_scan", False):
                shodan_key = self._get_shodan_key()
            
            # Always ask for OSINT keys in PHISHING mode (we need emails)
            if scan_mode == ScanMode.PHISHING or scan_mode != ScanMode.CUSTOM or module_selection.get("module_email_discovery", False):
                hunter_key = self._get_hunter_key()
                hibp_key = self._get_hibp_key()
                github_token = self._get_github_token()
            
            if scan_mode != ScanMode.CUSTOM or module_selection.get("module_vuln_lookup", False):
                nvd_key = self._get_nvd_key()
            
            # Step 7: OSINT Options (if OSINT enabled - always for PHISHING mode)
            osint_options = {}
            if scan_mode == ScanMode.PHISHING or scan_mode != ScanMode.CUSTOM or module_selection.get("module_email_discovery", False):
                osint_options = self._get_osint_options()
            
            # Step 8: Output Directory
            output_dir = self._get_output_directory()
            
            # Step 9: Additional Options
            options = self._get_additional_options()
            
            # Build ScanConfig with module selections
            # Determine if phishing is enabled (from Phishing mode OR Custom mode selection)
            phishing_enabled = scan_mode == ScanMode.PHISHING or module_selection.get("module_phishing", False)
            
            # Remove module_phishing from module_selection to avoid duplicate kwarg
            if "module_phishing" in module_selection:
                del module_selection["module_phishing"]
            
            self.config = ScanConfig(
                mode=scan_mode if scan_mode != ScanMode.PHISHING else ScanMode.PASSIVE,  # Phishing uses passive recon
                wordlist_dirs=Path(wordlist_dirs) if wordlist_dirs else None,
                wordlist_subdomains=Path(wordlist_subs) if wordlist_subs else None,
                scope_blacklist=scope_blacklist,
                shodan_api_key=shodan_key,
                hunter_api_key=hunter_key,
                nvd_api_key=nvd_key,
                github_token=github_token,
                hibp_api_key=hibp_key,
                use_system_dns=options.get("use_system_dns", True),  # Default to system DNS
                skip_osint=osint_options.get("skip_osint", False),
                verify_emails=osint_options.get("verify_emails", False),
                generate_permutations=osint_options.get("generate_permutations", False),
                verbose=options.get("verbose", False),
                output_dir=output_dir,
                # Phishing configuration
                module_phishing=phishing_enabled,
                smtp_host=phishing_config.get("smtp_host", "smtp.mailtrap.io"),
                smtp_port=phishing_config.get("smtp_port", 2525),
                smtp_username=phishing_config.get("smtp_username"),
                smtp_password=phishing_config.get("smtp_password"),
                phishing_template=phishing_config.get("phishing_template", "security_alert"),
                phishing_landing_page=phishing_config.get("landing_page", "security_alert"),
                # Custom module selections
                **module_selection,
            )
            
            self.targets = targets
            
            # Confirmation
            if self._confirm_settings():
                return self.config, self.targets
            else:
                print("\n[!] Scan cancelled by user.\n")
                return None, []
                
        except KeyboardInterrupt:
            print("\n\n[!] Wizard cancelled.\n")
            return None, []
    
    def _select_scan_mode(self) -> Optional[ScanMode]:
        """Prompt user to select scan mode."""
        choices = [
            questionary.Choice(
                title="🔍 Passive - OSINT + DNS only (no direct interaction)",
                value=ScanMode.PASSIVE,
            ),
            questionary.Choice(
                title="⚡ Active - Full scan with Dir Enum + Zone Transfer",
                value=ScanMode.ACTIVE,
            ),
            questionary.Choice(
                title="� Phishing - Recon + Phishing simulation campaign",
                value=ScanMode.PHISHING,
            ),
            questionary.Choice(
                title="🎛️  Custom - Select specific modules to run",
                value=ScanMode.CUSTOM,
            ),
        ]
        
        mode = questionary.select(
            "Choose Scan Mode:",
            choices=choices,
            style=WIZARD_STYLE,
            instruction="(Use arrow keys)",
        ).ask()
        
        if mode:
            mode_names = {
                ScanMode.PASSIVE: "PASSIVE",
                ScanMode.ACTIVE: "ACTIVE",
                ScanMode.PHISHING: "PHISHING",
                ScanMode.CUSTOM: "CUSTOM",
            }
            print(f"  ✓ Mode: {mode_names.get(mode, 'UNKNOWN')}\n")
        
        return mode
    
    def _select_modules(self) -> Optional[dict]:
        """
        Prompt user to select specific modules to run in Custom mode.
        Uses checkbox-style selection for granular control.
        
        Returns:
            Dictionary with module_* keys set to True/False
        """
        print("\n  📦 Select Modules to Run")
        print("  " + "-" * 40)
        print("  Use SPACE to toggle [x], ENTER to confirm\n")
        
        # Discovery modules
        discovery_choices = [
            questionary.Choice(
                title="🌐 Subdomain Enumeration (crt.sh)",
                value="module_subdomain_enum",
                checked=True,
            ),
            questionary.Choice(
                title="📡 DNS Resolution (A/AAAA records)",
                value="module_dns_resolution",
                checked=True,
            ),
            questionary.Choice(
                title="🔒 SSL Certificate Analysis",
                value="module_ssl_analysis",
                checked=True,
            ),
        ]
        
        discovery_selected = questionary.checkbox(
            "Discovery Modules:",
            choices=discovery_choices,
            style=WIZARD_STYLE,
            instruction="(Space to select, Enter to confirm)",
        ).ask()
        
        if discovery_selected is None:
            return None
        
        # Fingerprinting modules
        fingerprint_choices = [
            questionary.Choice(
                title="🔬 Technology Detection (Wappalyzer-style)",
                value="module_tech_detection",
                checked=True,
            ),
            questionary.Choice(
                title="🛡️  WAF Detection",
                value="module_waf_detection",
                checked=True,
            ),
            questionary.Choice(
                title="⚠️  Vulnerability Lookup (CVE/NVD)",
                value="module_vuln_lookup",
                checked=True,
            ),
        ]
        
        fingerprint_selected = questionary.checkbox(
            "Fingerprinting Modules:",
            choices=fingerprint_choices,
            style=WIZARD_STYLE,
            instruction="(Space to select, Enter to confirm)",
        ).ask()
        
        if fingerprint_selected is None:
            return None
        
        # OSINT modules
        osint_choices = [
            questionary.Choice(
                title="📧 Email Discovery (Hunter.io, scraping)",
                value="module_email_discovery",
                checked=True,
            ),
            questionary.Choice(
                title="👤 People/Employee Discovery",
                value="module_people_discovery",
                checked=True,
            ),
        ]
        
        osint_selected = questionary.checkbox(
            "OSINT Modules:",
            choices=osint_choices,
            style=WIZARD_STYLE,
            instruction="(Space to select, Enter to confirm)",
        ).ask()
        
        if osint_selected is None:
            return None
        
        # Active Recon modules (with warning)
        print("\n  ⚡ Active Recon (Direct target interaction)")
        active_choices = [
            questionary.Choice(
                title="📋 DNS Zone Transfer Attempt",
                value="module_zone_transfer",
                checked=False,
            ),
            questionary.Choice(
                title="📂 Directory Enumeration",
                value="module_dir_enum",
                checked=False,
            ),
        ]
        
        active_selected = questionary.checkbox(
            "Active Recon Modules (⚠️  sends requests to target):",
            choices=active_choices,
            style=WIZARD_STYLE,
            instruction="(Space to select, Enter to confirm)",
        ).ask()
        
        if active_selected is None:
            return None
        
        # Port Intelligence
        port_choices = [
            questionary.Choice(
                title="🔌 Port/Service Lookup (Shodan API)",
                value="module_port_scan",
                checked=False,
            ),
        ]
        
        port_selected = questionary.checkbox(
            "Port Intelligence:",
            choices=port_choices,
            style=WIZARD_STYLE,
            instruction="(Space to select, Enter to confirm)",
        ).ask()
        
        if port_selected is None:
            return None
        
        # Phishing Simulation
        print("\n  🎣 Phishing Simulation (Requires authorization)")
        phishing_choices = [
            questionary.Choice(
                title="🎣 Phishing Campaign (send simulated phishing emails)",
                value="module_phishing",
                checked=False,
            ),
        ]
        
        phishing_selected = questionary.checkbox(
            "Phishing Module (⚠️  requires explicit authorization):",
            choices=phishing_choices,
            style=WIZARD_STYLE,
            instruction="(Space to select, Enter to confirm)",
        ).ask()
        
        if phishing_selected is None:
            return None
        
        # Build module selection dict
        all_modules = [
            "module_subdomain_enum", "module_dns_resolution", "module_ssl_analysis",
            "module_tech_detection", "module_waf_detection", "module_vuln_lookup",
            "module_email_discovery", "module_people_discovery",
            "module_zone_transfer", "module_dir_enum",
            "module_port_scan", "module_phishing",
        ]
        
        selected = set(discovery_selected + fingerprint_selected + osint_selected + active_selected + port_selected + phishing_selected)
        module_selection = {mod: (mod in selected) for mod in all_modules}
        
        # Count selected
        enabled_count = sum(1 for v in module_selection.values() if v)
        print(f"\n  ✓ Selected {enabled_count} modules\n")
        
        # Show summary
        if discovery_selected:
            print(f"    Discovery:      {', '.join([m.replace('module_', '').replace('_', ' ').title() for m in discovery_selected])}")
        if fingerprint_selected:
            print(f"    Fingerprinting: {', '.join([m.replace('module_', '').replace('_', ' ').title() for m in fingerprint_selected])}")
        if osint_selected:
            print(f"    OSINT:          {', '.join([m.replace('module_', '').replace('_', ' ').title() for m in osint_selected])}")
        if active_selected:
            print(f"    Active Recon:   {', '.join([m.replace('module_', '').replace('_', ' ').title() for m in active_selected])}")
        if port_selected:
            print(f"    Port Intel:     {', '.join([m.replace('module_', '').replace('_', ' ').title() for m in port_selected])}")
        if phishing_selected:
            print(f"    Phishing:       🎣 Campaign Enabled")
        print()
        
        return module_selection
    
    def _configure_phishing(self) -> Optional[dict]:
        """
        Configure phishing simulation settings.
        
        Returns:
            Dictionary with phishing configuration
        """
        print("\n" + "=" * 60)
        print("  🎣 PHISHING SIMULATION CONFIGURATION")
        print("=" * 60)
        print("\n  ⚠️  WARNING: For AUTHORIZED security testing only!")
        print("  Ensure you have written permission before proceeding.\n")
        
        # Confirm authorization
        authorized = questionary.confirm(
            "Do you have explicit written authorization for this test?",
            default=False,
            style=WIZARD_STYLE,
        ).ask()
        
        if not authorized:
            print("\n  [!] Authorization required. Cannot proceed with phishing.\n")
            return None
        
        print("\n  📧 SMTP Configuration")
        print("  " + "-" * 40)
        
        # SMTP Host
        smtp_host = questionary.text(
            "SMTP Server Host:",
            default="smtp.mailtrap.io",
            style=WIZARD_STYLE,
        ).ask()
        
        if smtp_host is None:
            return None
        
        # SMTP Port
        smtp_port_str = questionary.text(
            "SMTP Server Port:",
            default="2525",
            style=WIZARD_STYLE,
        ).ask()
        
        if smtp_port_str is None:
            return None
        
        try:
            smtp_port = int(smtp_port_str)
        except ValueError:
            smtp_port = 2525
        
        # SMTP Username
        smtp_username = questionary.text(
            "SMTP Username:",
            style=WIZARD_STYLE,
        ).ask()
        
        if smtp_username is None:
            return None
        
        # SMTP Password
        smtp_password = questionary.password(
            "SMTP Password:",
            style=WIZARD_STYLE,
        ).ask()
        
        if smtp_password is None:
            return None
        
        print("\n  📝 Email Template")
        print("  " + "-" * 40)
        
        # Template selection
        template_choices = [
            questionary.Choice(
                title="🔒 Security Alert - Suspicious login attempt",
                value="security_alert",
            ),
            questionary.Choice(
                title="⏰ Password Expiry - Password update required",
                value="password_expiry",
            ),
            questionary.Choice(
                title="📄 Document Share - Shared document notification",
                value="document_share",
            ),
            questionary.Choice(
                title="🛠️ IT Support - Account verification request",
                value="it_support",
            ),
        ]
        
        phishing_template = questionary.select(
            "Select Phishing Email Template:",
            choices=template_choices,
            style=WIZARD_STYLE,
        ).ask()
        
        if phishing_template is None:
            return None
        
        # Landing page selection
        print("\n  🌐 Landing Page")
        print("  " + "-" * 40)
        
        landing_choices = [
            questionary.Choice(
                title="✨ Auto-Match - Use landing page matching email template (Recommended)",
                value=phishing_template,  # Auto-match to selected email template
            ),
            questionary.Choice(
                title="🔒 Security Alert - Account verification page",
                value="security_alert",
            ),
            questionary.Choice(
                title="🔐 Password Update - Password expiry page",
                value="password_expiry",
            ),
            questionary.Choice(
                title="📄 Document View - Shared document login",
                value="document_share",
            ),
            questionary.Choice(
                title="🛡️ IT Support - IT verification portal",
                value="it_support",
            ),
            questionary.Choice(
                title="🔷 Generic - Simple corporate login",
                value="generic",
            ),
            questionary.Choice(
                title="🪟 Microsoft - Microsoft 365 style",
                value="microsoft",
            ),
            questionary.Choice(
                title="🔴 Google - Google Workspace style",
                value="google",
            ),
        ]
        
        landing_page = questionary.select(
            "Select Landing Page Template:",
            choices=landing_choices,
            style=WIZARD_STYLE,
        ).ask()
        
        if landing_page is None:
            return None
        
        print(f"\n  ✓ SMTP Server: {smtp_host}:{smtp_port}")
        print(f"  ✓ Template: {phishing_template}")
        print(f"  ✓ Landing Page: {landing_page}\n")
        
        return {
            "smtp_host": smtp_host,
            "smtp_port": smtp_port,
            "smtp_username": smtp_username,
            "smtp_password": smtp_password,
            "phishing_template": phishing_template,
            "landing_page": landing_page,
        }
    
    def _select_targets(self) -> List[Target]:
        """Prompt user to select target(s)."""
        target_type = questionary.select(
            "Target Selection:",
            choices=[
                questionary.Choice(title="Single Target (domain)", value="single"),
                questionary.Choice(title="Multiple Targets (file)", value="file"),
            ],
            style=WIZARD_STYLE,
        ).ask()
        
        if target_type is None:
            return []
        
        if target_type == "file":
            return self._get_targets_from_file()
        else:
            return self._get_single_target()
    
    def _get_single_target(self) -> List[Target]:
        """Get a single target domain from user."""
        domain = questionary.text(
            "Enter target domain:",
            validate=lambda x: len(x.strip()) > 0 or "Domain cannot be empty",
            style=WIZARD_STYLE,
        ).ask()
        
        if domain:
            domain = domain.strip().lower()
            # Remove protocol if present
            if domain.startswith(("http://", "https://")):
                domain = domain.split("://")[1].split("/")[0]
            
            print(f"  ✓ Target: {domain}\n")
            return [Target(domain=domain)]
        
        return []
    
    def _get_targets_from_file(self) -> List[Target]:
        """Get targets from a file."""
        filepath = questionary.path(
            "Enter path to targets file:",
            validate=lambda x: Path(x).exists() or "File does not exist",
            style=WIZARD_STYLE,
        ).ask()
        
        if filepath:
            try:
                targets = Target.from_file(filepath)
                print(f"  ✓ Loaded {len(targets)} targets from {filepath}\n")
                return targets
            except Exception as e:
                print(f"  ✗ Error loading file: {e}\n")
                return []
        
        return []
    
    def _get_directory_wordlist(self) -> Optional[str]:
        """Get custom directory wordlist path (Active mode only)."""
        use_custom = questionary.confirm(
            "Use custom wordlist for directory enumeration?",
            default=False,
            style=WIZARD_STYLE,
        ).ask()
        
        if use_custom:
            path = questionary.path(
                "Enter path to directory wordlist:",
                validate=lambda x: Path(x).exists() or "File does not exist",
                style=WIZARD_STYLE,
            ).ask()
            
            if path:
                print(f"  ✓ Directory wordlist: {path}\n")
                return path
        
        print("  ✓ Using default directory wordlist\n")
        return None
    
    def _get_subdomain_wordlist(self) -> Optional[str]:
        """Get custom subdomain wordlist path."""
        use_custom = questionary.confirm(
            "Use custom wordlist for subdomain enumeration?",
            default=False,
            style=WIZARD_STYLE,
        ).ask()
        
        if use_custom:
            path = questionary.path(
                "Enter path to subdomain wordlist:",
                validate=lambda x: Path(x).exists() or "File does not exist",
                style=WIZARD_STYLE,
            ).ask()
            
            if path:
                print(f"  ✓ Subdomain wordlist: {path}\n")
                return path
        
        print("  ✓ Using default subdomain wordlist\n")
        return None
    
    def _get_scope_exclusions(self) -> List[str]:
        """Get out-of-scope subdomain patterns."""
        exclusions_str = questionary.text(
            "Enter out-of-scope subdomains (comma-separated, or leave empty):",
            default="",
            style=WIZARD_STYLE,
        ).ask()
        
        if exclusions_str:
            exclusions = [s.strip() for s in exclusions_str.split(",") if s.strip()]
            if exclusions:
                print(f"  ✓ Excluded patterns: {', '.join(exclusions)}\n")
                return exclusions
        
        print("  ✓ No scope exclusions\n")
        return []
    
    def _get_shodan_key(self) -> Optional[str]:
        """Get Shodan API key."""
        key = questionary.text(
            "Enter Shodan API Key (optional, press Enter to skip):",
            default="",
            style=WIZARD_STYLE,
        ).ask()
        
        if key and key.strip():
            print("  ✓ Shodan API key configured\n")
            return key.strip()
        
        print("  ○ Shodan API key not provided (port intel will be skipped)\n")
        return None
    
    def _get_hunter_key(self) -> Optional[str]:
        """Get Hunter.io API key."""
        key = questionary.text(
            "Enter Hunter.io API Key (optional, for email discovery):",
            default="",
            style=WIZARD_STYLE,
        ).ask()
        
        if key and key.strip():
            print("  ✓ Hunter.io API key configured\n")
            return key.strip()
        
        return None
    
    def _get_nvd_key(self) -> Optional[str]:
        """Get NVD API key."""
        key = questionary.text(
            "Enter NVD API Key (optional, for CVE lookups):",
            default="",
            style=WIZARD_STYLE,
        ).ask()
        
        if key and key.strip():
            print("  ✓ NVD API key configured\n")
            return key.strip()
        
        return None
    
    def _get_github_token(self) -> Optional[str]:
        """Get GitHub token for OSINT."""
        key = questionary.text(
            "Enter GitHub Token (optional, for code search):",
            default="",
            style=WIZARD_STYLE,
        ).ask()
        
        if key and key.strip():
            print("  ✓ GitHub token configured\n")
            return key.strip()
        
        return None
    
    def _get_hibp_key(self) -> Optional[str]:
        """Get Have I Been Pwned API key."""
        key = questionary.text(
            "Enter HIBP API Key (optional, for breach data):",
            default="",
            style=WIZARD_STYLE,
        ).ask()
        
        if key and key.strip():
            print("  ✓ HIBP API key configured\n")
            return key.strip()
        
        return None
    
    def _get_osint_options(self) -> dict:
        """Get OSINT-related options."""
        options = {}
        
        skip_osint = questionary.confirm(
            "Skip OSINT collection (emails, people)?",
            default=False,
            style=WIZARD_STYLE,
        ).ask()
        
        options["skip_osint"] = skip_osint
        
        if not skip_osint:
            # Only ask these if OSINT is enabled
            verify_emails = questionary.confirm(
                "Verify discovered emails (slower but more accurate)?",
                default=False,
                style=WIZARD_STYLE,
            ).ask()
            options["verify_emails"] = verify_emails
            
            generate_perms = questionary.confirm(
                "Generate email permutations from discovered names?",
                default=False,
                style=WIZARD_STYLE,
            ).ask()
            options["generate_permutations"] = generate_perms
            
            if verify_emails:
                print("  ✓ Email verification enabled\n")
            if generate_perms:
                print("  ✓ Email permutations enabled\n")
        else:
            print("  ○ OSINT collection will be skipped\n")
        
        return options
    
    def _get_output_directory(self) -> str:
        """Get output directory path."""
        output_dir = questionary.text(
            "Output directory (default: ./output):",
            default="./output",
            style=WIZARD_STYLE,
        ).ask()
        
        if output_dir:
            print(f"  ✓ Output: {output_dir}\n")
            return output_dir.strip()
        
        return "./output"
    
    def _get_additional_options(self) -> dict:
        """Get additional scan options."""
        options = {}
        
        # DNS settings (default to system DNS for better compatibility)
        use_system_dns = questionary.confirm(
            "Use system DNS instead of public DNS (8.8.8.8)?",
            default=True,  # Default to system DNS for better network compatibility
            style=WIZARD_STYLE,
        ).ask()
        
        options["use_system_dns"] = use_system_dns
        if use_system_dns:
            print("  ✓ Using system DNS\n")
        else:
            print("  ✓ Using public DNS (8.8.8.8, 1.1.1.1)\n")
        
        # Verbose mode
        verbose = questionary.confirm(
            "Enable verbose/debug logging?",
            default=False,
            style=WIZARD_STYLE,
        ).ask()
        
        options["verbose"] = verbose
        if verbose:
            print("  ✓ Verbose mode enabled\n")
        
        return options
    
    def _confirm_settings(self) -> bool:
        """Display summary and confirm settings."""
        print("\n" + "=" * 60)
        print("  📋 Scan Configuration Summary")
        print("=" * 60)
        
        if self.config.mode == ScanMode.PASSIVE:
            mode_name = "PASSIVE"
        elif self.config.mode == ScanMode.ACTIVE:
            mode_name = "ACTIVE"
        elif getattr(self.config, 'module_phishing', False):
            mode_name = "PHISHING"
        else:
            mode_name = "CUSTOM"
        
        print(f"  Mode:           {mode_name}")
        print(f"  Targets:        {len(self.targets)}")
        
        for target in self.targets[:5]:  # Show first 5
            print(f"                  - {target.domain}")
        if len(self.targets) > 5:
            print(f"                  ... and {len(self.targets) - 5} more")
        
        if self.config.scope_blacklist:
            print(f"  Exclusions:     {', '.join(self.config.scope_blacklist)}")
        
        if self.config.wordlist_dirs:
            print(f"  Dir Wordlist:   {self.config.wordlist_dirs}")
        
        # Show selected modules for Custom mode
        if self.config.mode == ScanMode.CUSTOM:
            print("\n  --- Selected Modules ---")
            
            # Discovery
            discovery_mods = []
            if getattr(self.config, 'module_subdomain_enum', False):
                discovery_mods.append("Subdomain Enum")
            if getattr(self.config, 'module_dns_resolution', False):
                discovery_mods.append("DNS Resolution")
            if getattr(self.config, 'module_ssl_analysis', False):
                discovery_mods.append("SSL Analysis")
            if discovery_mods:
                print(f"  Discovery:      {', '.join(discovery_mods)}")
            
            # Fingerprinting
            fingerprint_mods = []
            if getattr(self.config, 'module_tech_detection', False):
                fingerprint_mods.append("Tech Detection")
            if getattr(self.config, 'module_waf_detection', False):
                fingerprint_mods.append("WAF Detection")
            if getattr(self.config, 'module_vuln_lookup', False):
                fingerprint_mods.append("Vuln Lookup")
            if fingerprint_mods:
                print(f"  Fingerprint:    {', '.join(fingerprint_mods)}")
            
            # OSINT
            osint_mods = []
            if getattr(self.config, 'module_email_discovery', False):
                osint_mods.append("Email Discovery")
            if getattr(self.config, 'module_people_discovery', False):
                osint_mods.append("People Discovery")
            if osint_mods:
                print(f"  OSINT:          {', '.join(osint_mods)}")
            
            # Active Recon
            active_mods = []
            if getattr(self.config, 'module_zone_transfer', False):
                active_mods.append("Zone Transfer")
            if getattr(self.config, 'module_dir_enum', False):
                active_mods.append("Dir Enum")
            if active_mods:
                print(f"  Active Recon:   ⚡ {', '.join(active_mods)}")
            
            # Port Intel
            if getattr(self.config, 'module_port_scan', False):
                print(f"  Port Intel:     🔌 Shodan Lookup")
            
            # Phishing (in Custom mode)
            if getattr(self.config, 'module_phishing', False):
                print(f"  Phishing:       🎣 Campaign Enabled")
        
        # API Keys
        print("\n  --- API Keys ---")
        print(f"  Shodan:         {'✓ Configured' if self.config.shodan_api_key else '○ Not set'}")
        print(f"  Hunter.io:      {'✓ Configured' if self.config.hunter_api_key else '○ Not set'}")
        print(f"  NVD:            {'✓ Configured' if self.config.nvd_api_key else '○ Not set'}")
        print(f"  GitHub:         {'✓ Configured' if self.config.github_token else '○ Not set'}")
        print(f"  HIBP:           {'✓ Configured' if self.config.hibp_api_key else '○ Not set'}")
        
        # Options
        print("\n  --- Options ---")
        print(f"  Skip OSINT:     {'Yes' if getattr(self.config, 'skip_osint', False) else 'No'}")
        print(f"  Verify Emails:  {'Yes' if getattr(self.config, 'verify_emails', False) else 'No'}")
        print(f"  Email Perms:    {'Yes' if getattr(self.config, 'generate_permutations', False) else 'No'}")
        print(f"  System DNS:     {'Yes' if self.config.use_system_dns else 'No'}")
        print(f"  Verbose:        {'Yes' if getattr(self.config, 'verbose', False) else 'No'}")
        print(f"  Output:         {getattr(self.config, 'output_dir', './output')}")
        
        # Phishing Configuration
        if getattr(self.config, 'module_phishing', False):
            print("\n  --- Phishing Configuration ---")
            print(f"  SMTP Host:      {getattr(self.config, 'smtp_host', 'smtp.mailtrap.io')}")
            print(f"  SMTP Port:      {getattr(self.config, 'smtp_port', 2525)}")
            print(f"  SMTP User:      {'✓ Configured' if getattr(self.config, 'smtp_username', None) else '○ Not set'}")
            print(f"  SMTP Pass:      {'✓ Configured' if getattr(self.config, 'smtp_password', None) else '○ Not set'}")
            print(f"  Template:       {getattr(self.config, 'phishing_template', 'security_alert')}")
        
        print("=" * 60 + "\n")
        
        return questionary.confirm(
            "Start scan with these settings?",
            default=True,
            style=WIZARD_STYLE,
        ).ask()


def run_wizard() -> Tuple[Optional[ScanConfig], List[Target]]:
    """
    Convenience function to run the interactive wizard.
    
    Returns:
        Tuple of (ScanConfig, List[Target]) or (None, []) if cancelled
    """
    wizard = InteractiveWizard()
    return wizard.start()
