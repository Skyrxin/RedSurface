"""
Active Reconnaissance Module for RedSurface.

This module contains methods that directly interact with targets.
CRITICAL: These methods should ONLY run when scan mode is ACTIVE.
"""

import asyncio
from dataclasses import dataclass, field
from typing import List, Optional, Set, Dict, Any
from pathlib import Path

import dns.query
import dns.zone
import dns.resolver
import dns.rdatatype
import dns.exception
import httpx

from utils.logger import get_logger
from core.config import ScanConfig, ScanMode


# Default directory wordlist for quick enumeration
DEFAULT_DIRS = [
    "admin",
    "login",
    "backup",
    "backups",
    ".git",
    ".env",
    ".htaccess",
    ".htpasswd",
    "config",
    "wp-admin",
    "wp-login.php",
    "administrator",
    "phpmyadmin",
    "cpanel",
    "webmail",
    "api",
    "swagger",
    "graphql",
    "robots.txt",
    "sitemap.xml",
    ".well-known",
    "server-status",
    "server-info",
    "debug",
    "test",
    "dev",
    "staging",
    "console",
    "dashboard",
]


@dataclass
class ActiveReconResults:
    """Results from active reconnaissance."""
    
    zone_transfer_subdomains: Set[str] = field(default_factory=set)
    zone_transfer_records: List[Dict[str, Any]] = field(default_factory=list)
    zone_transfer_success: bool = False
    zone_transfer_ns: Optional[str] = None
    
    discovered_directories: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        """Export results to dictionary."""
        return {
            "zone_transfer": {
                "success": self.zone_transfer_success,
                "nameserver": self.zone_transfer_ns,
                "subdomains": list(self.zone_transfer_subdomains),
                "records_count": len(self.zone_transfer_records),
            },
            "directory_enumeration": {
                host: {
                    "found_count": len(dirs),
                    "directories": dirs,
                }
                for host, dirs in self.discovered_directories.items()
            },
        }


class ActiveRecon:
    """
    Active reconnaissance module for direct target interaction.
    
    WARNING: These methods communicate directly with the target.
    Only use when mode is set to ACTIVE and you have authorization.
    """
    
    def __init__(
        self,
        config: Optional[ScanConfig] = None,
        timeout: float = 10.0,
        max_concurrent: int = 20,
        user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    ):
        """
        Initialize ActiveRecon module.
        
        Args:
            config: ScanConfig instance with mode and settings
            timeout: Request timeout in seconds
            max_concurrent: Maximum concurrent HTTP requests
            user_agent: User-Agent header for HTTP requests
        """
        self.config = config or ScanConfig()
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.user_agent = user_agent
        self.logger = get_logger()
        self.results = ActiveReconResults()
    
    def _is_active_mode(self) -> bool:
        """Check if we're in active scanning mode or custom mode with active modules enabled."""
        if self.config.mode == ScanMode.ACTIVE:
            return True
        # In CUSTOM mode, check if active recon modules are enabled
        if self.config.mode == ScanMode.CUSTOM:
            return getattr(self.config, 'module_zone_transfer', False) or getattr(self.config, 'module_dir_enum', False)
        return False
    
    def _should_run_zone_transfer(self) -> bool:
        """Check if zone transfer should run."""
        if self.config.mode == ScanMode.ACTIVE:
            return True
        if self.config.mode == ScanMode.CUSTOM:
            return getattr(self.config, 'module_zone_transfer', False)
        return False
    
    def _should_run_dir_enum(self) -> bool:
        """Check if directory enumeration should run."""
        if self.config.mode == ScanMode.ACTIVE:
            return True
        if self.config.mode == ScanMode.CUSTOM:
            return getattr(self.config, 'module_dir_enum', False)
        return False
    
    def zone_transfer(self, domain: str) -> Set[str]:
        """
        Attempt DNS zone transfer (AXFR) against target domain.
        
        Most DNS servers deny zone transfers, but misconfigured servers
        may expose all DNS records for the domain.
        
        Args:
            domain: Target domain to attempt zone transfer on
            
        Returns:
            Set of discovered subdomains from zone transfer
        """
        if not self._should_run_zone_transfer():
            self.logger.debug("Zone transfer skipped - not enabled")
            return set()
        
        discovered_subdomains: Set[str] = set()
        self.logger.info(f"[Active] Attempting zone transfer for {domain}")
        
        try:
            # First, get NS records for the domain
            ns_records = []
            try:
                answers = dns.resolver.resolve(domain, "NS")
                ns_records = [str(rdata.target).rstrip(".") for rdata in answers]
                self.logger.debug(f"Found {len(ns_records)} NS records: {ns_records}")
            except dns.exception.DNSException as e:
                self.logger.warning(f"Could not resolve NS records for {domain}: {e}")
                return discovered_subdomains
            
            # Attempt zone transfer against each nameserver
            for ns in ns_records:
                self.logger.debug(f"Attempting AXFR against {ns}")
                try:
                    # Resolve NS hostname to IP
                    ns_ip = None
                    try:
                        ns_answers = dns.resolver.resolve(ns, "A")
                        ns_ip = str(ns_answers[0])
                    except dns.exception.DNSException:
                        self.logger.debug(f"Could not resolve NS {ns} to IP")
                        continue
                    
                    # Attempt zone transfer
                    zone = dns.zone.from_xfr(
                        dns.query.xfr(ns_ip, domain, timeout=self.timeout)
                    )
                    
                    # Zone transfer succeeded!
                    self.logger.warning(
                        f"[!] Zone transfer SUCCESSFUL against {ns} ({ns_ip})!"
                    )
                    self.results.zone_transfer_success = True
                    self.results.zone_transfer_ns = ns
                    
                    # Extract all records
                    for name, node in zone.nodes.items():
                        subdomain = str(name)
                        if subdomain != "@":
                            fqdn = f"{subdomain}.{domain}"
                            discovered_subdomains.add(fqdn)
                            self.results.zone_transfer_subdomains.add(fqdn)
                        
                        # Store record details
                        for rdataset in node.rdatasets:
                            for rdata in rdataset:
                                self.results.zone_transfer_records.append({
                                    "name": subdomain,
                                    "type": dns.rdatatype.to_text(rdataset.rdtype),
                                    "value": str(rdata),
                                    "ttl": rdataset.ttl,
                                })
                    
                    self.logger.info(
                        f"Extracted {len(discovered_subdomains)} subdomains from zone transfer"
                    )
                    # One successful transfer is enough
                    break
                    
                except dns.query.TransferError:
                    self.logger.debug(f"Zone transfer denied by {ns}")
                except dns.exception.FormError:
                    self.logger.debug(f"Zone transfer format error from {ns}")
                except dns.exception.Timeout:
                    self.logger.debug(f"Zone transfer timeout from {ns}")
                except Exception as e:
                    self.logger.debug(f"Zone transfer error from {ns}: {e}")
            
            if not self.results.zone_transfer_success:
                self.logger.info(f"Zone transfer denied by all nameservers (expected)")
                
        except Exception as e:
            self.logger.error(f"Zone transfer attempt failed: {e}")
        
        return discovered_subdomains
    
    async def directory_enum(
        self,
        url: str,
        wordlist_path: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Enumerate directories and files on a web server.
        
        Args:
            url: Base URL to enumerate (e.g., https://example.com)
            wordlist_path: Path to wordlist file, or None for default list
            
        Returns:
            List of discovered directories/files with status codes
        """
        if not self._should_run_dir_enum():
            self.logger.debug("Directory enumeration skipped - not enabled")
            return []
        
        # Normalize URL
        url = url.rstrip("/")
        self.logger.info(f"[Active] Directory enumeration on {url}")
        
        # Load wordlist
        wordlist: List[str] = []
        if wordlist_path:
            try:
                path = Path(wordlist_path)
                if path.exists():
                    with open(path, "r", encoding="utf-8") as f:
                        wordlist = [
                            line.strip() 
                            for line in f 
                            if line.strip() and not line.startswith("#")
                        ]
                    self.logger.debug(f"Loaded {len(wordlist)} entries from {wordlist_path}")
                else:
                    self.logger.warning(f"Wordlist not found: {wordlist_path}, using defaults")
                    wordlist = DEFAULT_DIRS.copy()
            except Exception as e:
                self.logger.warning(f"Error loading wordlist: {e}, using defaults")
                wordlist = DEFAULT_DIRS.copy()
        else:
            wordlist = DEFAULT_DIRS.copy()
        
        # Also try loading from config
        if self.config.wordlist_dirs and self.config.wordlist_dirs.exists():
            config_wordlist = self.config.load_directory_wordlist()
            if config_wordlist:
                wordlist.extend(config_wordlist)
                wordlist = list(set(wordlist))  # Deduplicate
        
        found_dirs: List[Dict[str, Any]] = []
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def check_path(client: httpx.AsyncClient, path: str) -> Optional[Dict[str, Any]]:
            """Check a single path."""
            async with semaphore:
                target_url = f"{url}/{path.lstrip('/')}"
                try:
                    response = await client.get(
                        target_url,
                        follow_redirects=False,
                        timeout=self.timeout,
                    )
                    
                    # Interesting status codes
                    if response.status_code in [200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500]:
                        result = {
                            "url": target_url,
                            "path": path,
                            "status_code": response.status_code,
                            "content_length": len(response.content),
                            "content_type": response.headers.get("content-type", ""),
                        }
                        
                        # Log based on status
                        if response.status_code == 200:
                            self.logger.info(f"  [200] Found: {target_url}")
                        elif response.status_code == 403:
                            self.logger.info(f"  [403] Forbidden: {target_url}")
                        elif response.status_code in [301, 302, 307, 308]:
                            redirect_loc = response.headers.get("location", "")
                            result["redirect"] = redirect_loc
                            self.logger.debug(f"  [{response.status_code}] Redirect: {target_url} -> {redirect_loc}")
                        elif response.status_code == 401:
                            self.logger.info(f"  [401] Auth Required: {target_url}")
                        
                        return result
                    
                    # 404 is noise, ignore
                    return None
                    
                except httpx.TimeoutException:
                    self.logger.debug(f"Timeout: {target_url}")
                    return None
                except httpx.RequestError as e:
                    self.logger.debug(f"Request error for {target_url}: {e}")
                    return None
        
        # Run enumeration
        try:
            async with httpx.AsyncClient(
                headers={"User-Agent": self.user_agent},
                verify=False,
            ) as client:
                tasks = [check_path(client, path) for path in wordlist]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for result in results:
                    if isinstance(result, dict):
                        found_dirs.append(result)
        
        except Exception as e:
            self.logger.error(f"Directory enumeration error: {e}")
        
        # Store results - extend existing list instead of overwriting
        host = url.split("://")[-1].split("/")[0]
        if host not in self.results.discovered_directories:
            self.results.discovered_directories[host] = []
        
        # Avoid duplicates when extending
        existing_paths = {d.get("path") for d in self.results.discovered_directories[host]}
        for dir_info in found_dirs:
            if dir_info.get("path") not in existing_paths:
                self.results.discovered_directories[host].append(dir_info)
                existing_paths.add(dir_info.get("path"))
        
        self.logger.info(f"Directory enumeration complete: {len(found_dirs)} interesting paths found")
        return found_dirs
    
    async def run(self, target) -> ActiveReconResults:
        """
        Orchestrate all active reconnaissance methods.
        
        CRITICAL: This method checks if mode is ACTIVE or CUSTOM with active modules enabled.
        If mode is PASSIVE, it returns immediately with empty results.
        
        Args:
            target: Target instance with domain and discovered assets
            
        Returns:
            ActiveReconResults with all findings
        """
        # CRITICAL: Check mode before any active operations
        # Allow ACTIVE mode or CUSTOM mode with active modules enabled
        if not self._is_active_mode():
            self.logger.info("[Active Recon] Skipped - no active modules enabled")
            return self.results
        
        mode_str = "CUSTOM" if self.config.mode == ScanMode.CUSTOM else "ACTIVE"
        self.logger.info("=" * 50)
        self.logger.info(f"[Active Recon] Starting active reconnaissance ({mode_str} mode)")
        self.logger.warning("[!] Active mode enabled - direct target interaction")
        self.logger.info("=" * 50)
        
        # Phase 1: DNS Zone Transfer (only if enabled)
        if self._should_run_zone_transfer():
            self.logger.info("\n[Phase 1] DNS Zone Transfer Attempt")
            zone_subdomains = self.zone_transfer(target.domain)
            
            # Add discovered subdomains to target
            if zone_subdomains:
                target.subdomains.update(zone_subdomains)
                self.logger.info(f"Added {len(zone_subdomains)} subdomains from zone transfer")
        else:
            self.logger.debug("[Phase 1] Zone Transfer skipped - not enabled")
        
        # Phase 2: Directory Enumeration (only if enabled)
        if self._should_run_dir_enum():
            self.logger.info("\n[Phase 2] Directory Enumeration")
            
            # Build list of URLs to enumerate
            urls_to_enum = []
            
            # Main domain
            urls_to_enum.append(f"https://{target.domain}")
            urls_to_enum.append(f"http://{target.domain}")
            
            # Discovered subdomains (limit to avoid too many requests)
            MAX_SUBDOMAINS_TO_ENUM = 10
            subdomains_list = list(target.subdomains)[:MAX_SUBDOMAINS_TO_ENUM]
            
            for subdomain in subdomains_list:
                urls_to_enum.append(f"https://{subdomain}")
            
            # Also check any discovered web services from fingerprinting
            if hasattr(target, "services"):
                for ip, services in target.services.items():
                    for service in services:
                        if service.get("service") in ["http", "https"]:
                            port = service.get("port", 80)
                            scheme = "https" if port == 443 or service.get("service") == "https" else "http"
                            urls_to_enum.append(f"{scheme}://{ip}:{port}")
            
            # Deduplicate
            urls_to_enum = list(set(urls_to_enum))
            self.logger.info(f"Enumerating {len(urls_to_enum)} URLs")
            
            # Run directory enumeration on each URL
            wordlist_path = str(self.config.wordlist_dirs) if self.config.wordlist_dirs else None
            
            for url in urls_to_enum:
                try:
                    await self.directory_enum(url, wordlist_path)
                except Exception as e:
                    self.logger.debug(f"Directory enum failed for {url}: {e}")
        else:
            self.logger.debug("[Phase 2] Directory Enumeration skipped - not enabled")
        
        # Summary
        total_dirs = sum(len(d) for d in self.results.discovered_directories.values())
        self.logger.info("=" * 50)
        self.logger.info("[Active Recon] Complete")
        self.logger.info(f"  Zone Transfer: {'SUCCESS' if self.results.zone_transfer_success else 'Denied/Skipped'}")
        self.logger.info(f"  Subdomains from AXFR: {len(self.results.zone_transfer_subdomains)}")
        self.logger.info(f"  Interesting Paths: {total_dirs}")
        self.logger.info("=" * 50)
        
        return self.results
