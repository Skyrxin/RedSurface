"""
Infrastructure Discovery Module for RedSurface.
Handles DNS resolution, CNAME extraction, and cloud provider detection.
"""

import asyncio
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
import dns.resolver
import dns.asyncresolver

from utils.logger import get_logger


# Cloud provider signature patterns (CNAME -> Provider mapping)
CLOUD_SIGNATURES: Dict[str, str] = {
    # AWS
    "amazonaws.com": "AWS",
    "cloudfront.net": "AWS CloudFront",
    "elasticbeanstalk.com": "AWS Elastic Beanstalk",
    "elb.amazonaws.com": "AWS ELB",
    "s3.amazonaws.com": "AWS S3",
    "awsglobalaccelerator.com": "AWS Global Accelerator",
    # Azure
    "azurewebsites.net": "Azure App Service",
    "azure-api.net": "Azure API Management",
    "azureedge.net": "Azure CDN",
    "cloudapp.azure.com": "Azure Cloud",
    "azurecontainer.io": "Azure Container",
    "database.windows.net": "Azure SQL",
    "blob.core.windows.net": "Azure Blob Storage",
    "trafficmanager.net": "Azure Traffic Manager",
    # Google Cloud
    "googleapis.com": "Google Cloud",
    "appspot.com": "Google App Engine",
    "cloudfunctions.net": "Google Cloud Functions",
    "run.app": "Google Cloud Run",
    "storage.googleapis.com": "Google Cloud Storage",
    # Cloudflare
    "cloudflare.com": "Cloudflare",
    "cdn.cloudflare.net": "Cloudflare CDN",
    # Fastly
    "fastly.net": "Fastly",
    "fastlylb.net": "Fastly",
    # Akamai
    "akamai.net": "Akamai",
    "akamaiedge.net": "Akamai",
    "akamaitechnologies.com": "Akamai",
    # Heroku
    "herokuapp.com": "Heroku",
    "herokussl.com": "Heroku",
    # DigitalOcean
    "digitaloceanspaces.com": "DigitalOcean Spaces",
    "ondigitalocean.app": "DigitalOcean App Platform",
    # Vercel
    "vercel.app": "Vercel",
    "now.sh": "Vercel",
    # Netlify
    "netlify.app": "Netlify",
    "netlify.com": "Netlify",
    # GitHub
    "github.io": "GitHub Pages",
    "githubusercontent.com": "GitHub",
}

# Common subdomain wordlist (small mock list for testing)
COMMON_SUBDOMAINS: List[str] = [
    "www",
    "mail",
    "ftp",
    "admin",
    "api",
    "dev",
    "staging",
    "test",
    "blog",
    "shop",
    "store",
    "app",
    "portal",
    "secure",
    "vpn",
    "remote",
    "webmail",
    "mx",
    "ns1",
    "ns2",
    "cdn",
    "static",
    "assets",
    "img",
    "images",
    "media",
    "video",
    "docs",
    "help",
    "support",
    "status",
    "monitor",
    "grafana",
    "jenkins",
    "gitlab",
    "git",
    "ci",
    "beta",
    "alpha",
    "demo",
    "sandbox",
    "uat",
    "prod",
    "production",
    "internal",
    "intranet",
    "extranet",
    "m",
    "mobile",
]


@dataclass
class DiscoveredAsset:
    """Represents a discovered infrastructure asset."""
    
    hostname: str
    ips: List[str] = field(default_factory=list)
    cnames: List[str] = field(default_factory=list)
    cloud_providers: List[str] = field(default_factory=list)
    is_alive: bool = False
    error: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert asset to dictionary representation."""
        return {
            "hostname": self.hostname,
            "ips": self.ips,
            "cnames": self.cnames,
            "cloud_providers": self.cloud_providers,
            "is_alive": self.is_alive,
            "error": self.error,
        }


class InfrastructureDiscoverer:
    """
    Discovers infrastructure assets through DNS enumeration and cloud detection.
    
    Features:
        - Async DNS resolution (A, AAAA, CNAME records)
        - Cloud provider detection from CNAME patterns
        - Subdomain enumeration with configurable wordlist
    """

    # Public DNS servers for reliable resolution
    PUBLIC_DNS_SERVERS = [
        "8.8.8.8",        # Google
        "8.8.4.4",        # Google
        "1.1.1.1",        # Cloudflare
        "1.0.0.1",        # Cloudflare
        "9.9.9.9",        # Quad9
    ]

    def __init__(
        self,
        wordlist: Optional[List[str]] = None,
        timeout: float = 3.0,
        max_concurrent: int = 50,
        dns_servers: Optional[List[str]] = None,
    ) -> None:
        """
        Initialize the infrastructure discoverer.

        Args:
            wordlist: Custom subdomain wordlist (default: built-in common list)
            timeout: DNS query timeout in seconds
            max_concurrent: Maximum concurrent DNS queries
            dns_servers: Custom DNS servers (default: public DNS servers)
        """
        self.wordlist = wordlist or COMMON_SUBDOMAINS
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.dns_servers = dns_servers or self.PUBLIC_DNS_SERVERS
        self.logger = get_logger()
        self._resolver: Optional[dns.asyncresolver.Resolver] = None

    def _get_resolver(self) -> dns.asyncresolver.Resolver:
        """Get or create the async DNS resolver with public DNS servers."""
        if self._resolver is None:
            self._resolver = dns.asyncresolver.Resolver()
            self._resolver.nameservers = self.dns_servers
            self._resolver.timeout = self.timeout
            self._resolver.lifetime = self.timeout * 2
        return self._resolver

    async def resolve_dns(self, hostname: str) -> DiscoveredAsset:
        """
        Asynchronously resolve DNS records for a hostname.

        Args:
            hostname: The hostname to resolve

        Returns:
            DiscoveredAsset with IPs, CNAMEs, and cloud provider info
        """
        asset = DiscoveredAsset(hostname=hostname)
        resolver = self._get_resolver()

        # Resolve CNAME records first
        try:
            cname_response = await resolver.resolve(hostname, "CNAME")
            for rdata in cname_response:
                cname = str(rdata.target).rstrip(".")
                asset.cnames.append(cname)
                # Detect cloud provider from CNAME
                provider = self.detect_cloud_provider(cname)
                if provider and provider not in asset.cloud_providers:
                    asset.cloud_providers.append(provider)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass  # No CNAME record, that's okay
        except dns.exception.Timeout:
            self.logger.debug(f"CNAME timeout for {hostname}")
        except Exception as e:
            self.logger.debug(f"CNAME error for {hostname}: {e}")

        # Resolve A records (IPv4)
        try:
            a_response = await resolver.resolve(hostname, "A")
            for rdata in a_response:
                ip = str(rdata.address)
                if ip not in asset.ips:
                    asset.ips.append(ip)
            asset.is_alive = True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass  # No A record
        except dns.exception.Timeout:
            asset.error = "DNS timeout"
            self.logger.debug(f"A record timeout for {hostname}")
        except Exception as e:
            asset.error = str(e)
            self.logger.debug(f"A record error for {hostname}: {e}")

        # Resolve AAAA records (IPv6)
        try:
            aaaa_response = await resolver.resolve(hostname, "AAAA")
            for rdata in aaaa_response:
                ip = str(rdata.address)
                if ip not in asset.ips:
                    asset.ips.append(ip)
            asset.is_alive = True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass  # No AAAA record
        except dns.exception.Timeout:
            self.logger.debug(f"AAAA record timeout for {hostname}")
        except Exception as e:
            self.logger.debug(f"AAAA record error for {hostname}: {e}")

        return asset

    def detect_cloud_provider(self, cname: str) -> Optional[str]:
        """
        Detect cloud provider from a CNAME record.

        Args:
            cname: The CNAME value to check

        Returns:
            Cloud provider name if detected, None otherwise
        """
        cname_lower = cname.lower()
        for signature, provider in CLOUD_SIGNATURES.items():
            if signature in cname_lower:
                return provider
        return None

    async def _enumerate_subdomain(
        self,
        subdomain: str,
        domain: str,
        semaphore: asyncio.Semaphore,
    ) -> Optional[DiscoveredAsset]:
        """
        Enumerate a single subdomain with rate limiting.

        Args:
            subdomain: Subdomain prefix to test
            domain: Base domain
            semaphore: Concurrency limiter

        Returns:
            DiscoveredAsset if found, None otherwise
        """
        hostname = f"{subdomain}.{domain}"
        async with semaphore:
            asset = await self.resolve_dns(hostname)
            if asset.is_alive:
                self.logger.debug(f"Found: {hostname} -> {asset.ips}")
                return asset
            return None

    async def run(self, target_domain: str) -> List[DiscoveredAsset]:
        """
        Run infrastructure discovery on a target domain.

        Enumerates common subdomains, resolves DNS, and detects cloud providers.

        Args:
            target_domain: The target domain to scan

        Returns:
            List of discovered assets with IPs, CNAMEs, and cloud info
        """
        self.logger.info(f"Starting infrastructure discovery on {target_domain}")
        discovered_assets: List[DiscoveredAsset] = []

        # First, resolve the root domain
        self.logger.debug(f"Resolving root domain: {target_domain}")
        root_asset = await self.resolve_dns(target_domain)
        if root_asset.is_alive:
            discovered_assets.append(root_asset)
            self.logger.info(
                f"Root domain resolved: {target_domain} -> {root_asset.ips}"
            )

        # Enumerate subdomains concurrently with rate limiting
        semaphore = asyncio.Semaphore(self.max_concurrent)
        tasks = [
            self._enumerate_subdomain(sub, target_domain, semaphore)
            for sub in self.wordlist
        ]

        self.logger.info(f"Enumerating {len(self.wordlist)} potential subdomains...")
        
        # Process results as they complete
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, DiscoveredAsset) and result.is_alive:
                discovered_assets.append(result)
            elif isinstance(result, Exception):
                self.logger.debug(f"Subdomain enumeration error: {result}")

        # Summary
        alive_count = len(discovered_assets)
        cloud_count = sum(1 for a in discovered_assets if a.cloud_providers)
        
        self.logger.info(
            f"Discovery complete: {alive_count} assets found, "
            f"{cloud_count} with cloud services detected"
        )

        return discovered_assets
