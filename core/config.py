"""
Configuration management for RedSurface scans.
Provides centralized scan configuration with scope management and API keys.
"""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional
import fnmatch
import re


class ScanMode(Enum):
    """Scan mode enumeration."""
    PASSIVE = "passive"    # Only passive reconnaissance (no direct interaction)
    ACTIVE = "active"      # Active scanning (direct requests, fuzzing, etc.)
    CUSTOM = "custom"      # Custom mode with user-selected modules
    PHISHING = "phishing"  # Recon + Phishing simulation campaign


# Default wordlists (relative to project root or absolute paths)
DEFAULT_SUBDOMAIN_WORDLIST = Path(__file__).parent.parent / "wordlists" / "subdomains.txt"
DEFAULT_DIRS_WORDLIST = Path(__file__).parent.parent / "wordlists" / "directories.txt"


@dataclass
class ScanConfig:
    """
    Central configuration for RedSurface scans.
    
    Attributes:
        wordlist_subdomains: Path to subdomain wordlist for enumeration
        wordlist_dirs: Path to directory wordlist for fuzzing
        mode: Scan mode (PASSIVE or ACTIVE)
        scope_blacklist: List of patterns for out-of-scope subdomains
        shodan_api_key: Shodan API key for port/service lookup
        dns_timeout: DNS query timeout in seconds
        http_timeout: HTTP request timeout in seconds
        max_concurrent: Maximum concurrent connections
        use_system_dns: Use system DNS instead of public DNS servers
    """
    wordlist_subdomains: Optional[Path] = None
    wordlist_dirs: Optional[Path] = None
    mode: ScanMode = ScanMode.PASSIVE
    scope_blacklist: List[str] = field(default_factory=list)
    shodan_api_key: Optional[str] = None
    
    # Network settings
    dns_timeout: float = 5.0  # Balanced timeout for system DNS
    http_timeout: float = 10.0
    max_concurrent: int = 100  # Increased for faster parallel resolution
    use_system_dns: bool = True  # Use system DNS by default (more reliable)
    
    # API Keys
    nvd_api_key: Optional[str] = None
    hunter_api_key: Optional[str] = None
    github_token: Optional[str] = None
    hibp_api_key: Optional[str] = None
    
    # OSINT Options
    skip_osint: bool = False
    verify_emails: bool = False
    generate_permutations: bool = False
    
    # Output Options
    verbose: bool = False
    output_dir: str = "./output"
    
    # Custom Mode - Module Selection
    # Discovery modules
    module_subdomain_enum: bool = True      # crt.sh subdomain discovery
    module_dns_resolution: bool = True      # DNS A/AAAA resolution
    module_ssl_analysis: bool = True        # SSL certificate analysis
    
    # Fingerprinting modules
    module_tech_detection: bool = True      # Technology fingerprinting
    module_waf_detection: bool = True       # WAF detection
    module_vuln_lookup: bool = True         # CVE/vulnerability lookup
    
    # OSINT modules
    module_email_discovery: bool = True     # Email harvesting
    module_people_discovery: bool = True    # People/employee discovery
    
    # Active Recon modules (require ACTIVE or CUSTOM mode)
    module_zone_transfer: bool = False      # DNS zone transfer attempts
    module_dir_enum: bool = False           # Directory enumeration
    
    # Port Intelligence
    module_port_scan: bool = False          # Shodan port lookup
    
    # Phishing Simulation
    module_phishing: bool = False           # Phishing simulation module
    smtp_host: str = "smtp.mailtrap.io"
    smtp_port: int = 2525
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = None
    phishing_template: str = "security_alert"
    phishing_landing_page: str = "security_alert"  # Landing page template

    def __post_init__(self) -> None:
        """Initialize default wordlist paths if not provided."""
        if self.wordlist_subdomains is None:
            self.wordlist_subdomains = DEFAULT_SUBDOMAIN_WORDLIST
        elif isinstance(self.wordlist_subdomains, str):
            self.wordlist_subdomains = Path(self.wordlist_subdomains)
            
        if self.wordlist_dirs is None:
            self.wordlist_dirs = DEFAULT_DIRS_WORDLIST
        elif isinstance(self.wordlist_dirs, str):
            self.wordlist_dirs = Path(self.wordlist_dirs)
        
        # Normalize blacklist patterns
        self.scope_blacklist = [p.lower().strip() for p in self.scope_blacklist if p.strip()]

    def is_in_scope(self, subdomain: str) -> bool:
        """
        Check if a subdomain is within scope (not blacklisted).
        
        Args:
            subdomain: The subdomain to check
            
        Returns:
            True if in scope (not blacklisted), False if out of scope
        """
        subdomain = subdomain.lower().strip()
        
        for pattern in self.scope_blacklist:
            # Exact match
            if subdomain == pattern:
                return False
            
            # Wildcard match (e.g., *.dev.example.com or dev.*)
            if fnmatch.fnmatch(subdomain, pattern):
                return False
            
            # Suffix match (e.g., blacklist "dev.example.com" blocks "api.dev.example.com")
            if subdomain.endswith(f".{pattern}"):
                return False
            
            # Regex pattern (if starts with ^)
            if pattern.startswith("^"):
                try:
                    if re.match(pattern, subdomain):
                        return False
                except re.error:
                    pass  # Invalid regex, skip
        
        return True

    def is_active_mode(self) -> bool:
        """Check if scan is in active mode."""
        return self.mode == ScanMode.ACTIVE

    def is_passive_mode(self) -> bool:
        """Check if scan is in passive mode."""
        return self.mode == ScanMode.PASSIVE

    def is_custom_mode(self) -> bool:
        """Check if scan is in custom mode."""
        return self.mode == ScanMode.CUSTOM

    def should_run_discovery(self) -> bool:
        """Check if any discovery modules are enabled."""
        return self.module_subdomain_enum or self.module_dns_resolution

    def should_run_fingerprinting(self) -> bool:
        """Check if any fingerprinting modules are enabled."""
        return self.module_tech_detection or self.module_waf_detection

    def should_run_osint(self) -> bool:
        """Check if any OSINT modules are enabled."""
        if self.skip_osint:
            return False
        return self.module_email_discovery or self.module_people_discovery

    def should_run_active_recon(self) -> bool:
        """Check if any active recon modules are enabled."""
        if self.is_passive_mode():
            return False
        return self.module_zone_transfer or self.module_dir_enum

    def should_run_port_intel(self) -> bool:
        """Check if port intelligence is enabled."""
        return self.module_port_scan and bool(self.shodan_api_key)

    def load_subdomain_wordlist(self) -> List[str]:
        """
        Load subdomain wordlist from file.
        
        Returns:
            List of subdomain prefixes to enumerate
        """
        if self.wordlist_subdomains and self.wordlist_subdomains.exists():
            try:
                with open(self.wordlist_subdomains, "r", encoding="utf-8") as f:
                    return [line.strip() for line in f if line.strip() and not line.startswith("#")]
            except Exception:
                pass
        return []

    def load_directory_wordlist(self) -> List[str]:
        """
        Load directory wordlist from file.
        
        Returns:
            List of directory paths to fuzz
        """
        if self.wordlist_dirs and self.wordlist_dirs.exists():
            try:
                with open(self.wordlist_dirs, "r", encoding="utf-8") as f:
                    return [line.strip() for line in f if line.strip() and not line.startswith("#")]
            except Exception:
                pass
        return []

    def to_dict(self) -> dict:
        """Export configuration to dictionary."""
        config_dict = {
            "wordlist_subdomains": str(self.wordlist_subdomains) if self.wordlist_subdomains else None,
            "wordlist_dirs": str(self.wordlist_dirs) if self.wordlist_dirs else None,
            "mode": self.mode.value,
            "scope_blacklist": self.scope_blacklist,
            "has_shodan_key": bool(self.shodan_api_key),
            "has_nvd_key": bool(self.nvd_api_key),
            "has_hunter_key": bool(self.hunter_api_key),
            "has_github_token": bool(self.github_token),
            "dns_timeout": self.dns_timeout,
            "http_timeout": self.http_timeout,
            "max_concurrent": self.max_concurrent,
            "use_system_dns": self.use_system_dns,
        }
        
        # Add custom mode module flags if applicable
        if self.mode == ScanMode.CUSTOM:
            config_dict["modules_enabled"] = {
                "subdomain_enum": self.module_subdomain_enum,
                "dns_resolution": self.module_dns_resolution,
                "ssl_analysis": self.module_ssl_analysis,
                "tech_detection": self.module_tech_detection,
                "waf_detection": self.module_waf_detection,
                "vuln_lookup": self.module_vuln_lookup,
                "email_discovery": self.module_email_discovery,
                "people_discovery": self.module_people_discovery,
                "zone_transfer": self.module_zone_transfer,
                "dir_enum": self.module_dir_enum,
                "port_scan": self.module_port_scan,
                "phishing": self.module_phishing,
            }
        
        return config_dict

    @classmethod
    def from_args(cls, args) -> "ScanConfig":
        """
        Create ScanConfig from argparse Namespace.
        
        Args:
            args: Parsed argparse arguments
            
        Returns:
            Configured ScanConfig instance
        """
        # Parse mode
        mode = ScanMode.PASSIVE
        if hasattr(args, "mode") and args.mode:
            mode = ScanMode.ACTIVE if args.mode.lower() == "active" else ScanMode.PASSIVE
        
        # Parse blacklist
        blacklist = []
        if hasattr(args, "exclude") and args.exclude:
            blacklist = [s.strip() for s in args.exclude.split(",") if s.strip()]
        
        # Parse wordlist paths
        wordlist_subs = None
        if hasattr(args, "wordlist_subs") and args.wordlist_subs:
            wordlist_subs = Path(args.wordlist_subs)
        
        wordlist_dirs = None
        if hasattr(args, "wordlist_dirs") and args.wordlist_dirs:
            wordlist_dirs = Path(args.wordlist_dirs)
        
        return cls(
            wordlist_subdomains=wordlist_subs,
            wordlist_dirs=wordlist_dirs,
            mode=mode,
            scope_blacklist=blacklist,
            shodan_api_key=getattr(args, "shodan_key", None),
            nvd_api_key=getattr(args, "nvd_key", None),
            hunter_api_key=getattr(args, "hunter_key", None),
            github_token=getattr(args, "github_token", None),
            hibp_api_key=getattr(args, "hibp_key", None),
            use_system_dns=getattr(args, "use_system_dns", False),
        )
