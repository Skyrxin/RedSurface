"""
Infrastructure Discovery Module for RedSurface.
Handles DNS resolution, CNAME extraction, crt.sh subdomain discovery,
SSL certificate analysis, and cloud provider detection.
"""

import asyncio
import ssl
import socket
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set
import dns.resolver
import dns.asyncresolver
import httpx

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
class SSLCertInfo:
    """SSL/TLS certificate information."""
    
    subject: str = ""
    issuer: str = ""
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    days_until_expiry: Optional[int] = None
    san_domains: List[str] = field(default_factory=list)
    serial_number: str = ""
    signature_algorithm: str = ""
    is_expired: bool = False
    is_self_signed: bool = False
    
    def to_dict(self) -> dict:
        """Convert to dictionary representation."""
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "not_before": str(self.not_before) if self.not_before else None,
            "not_after": str(self.not_after) if self.not_after else None,
            "days_until_expiry": self.days_until_expiry,
            "san_domains": self.san_domains,
            "serial_number": self.serial_number,
            "signature_algorithm": self.signature_algorithm,
            "is_expired": self.is_expired,
            "is_self_signed": self.is_self_signed,
        }


@dataclass
class DiscoveredAsset:
    """Represents a discovered infrastructure asset."""
    
    hostname: str
    ips: List[str] = field(default_factory=list)
    cnames: List[str] = field(default_factory=list)
    cloud_providers: List[str] = field(default_factory=list)
    ssl_cert: Optional[SSLCertInfo] = None
    is_alive: bool = False
    error: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert asset to dictionary representation."""
        return {
            "hostname": self.hostname,
            "ips": self.ips,
            "cnames": self.cnames,
            "cloud_providers": self.cloud_providers,
            "ssl_cert": self.ssl_cert.to_dict() if self.ssl_cert else None,
            "is_alive": self.is_alive,
            "error": self.error,
        }


class InfrastructureDiscoverer:
    """
    Discovers infrastructure assets through DNS enumeration and cloud detection.
    
    Features:
        - Async DNS resolution (A, AAAA, CNAME records)
        - crt.sh certificate transparency subdomain discovery
        - SSL/TLS certificate analysis
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
        use_crtsh: bool = True,
        analyze_ssl: bool = True,
        use_system_dns: bool = False,
    ) -> None:
        """
        Initialize the infrastructure discoverer.

        Args:
            wordlist: Custom subdomain wordlist (default: built-in common list)
            timeout: DNS query timeout in seconds
            max_concurrent: Maximum concurrent DNS queries
            dns_servers: Custom DNS servers (default: public DNS servers)
            use_crtsh: Enable crt.sh subdomain discovery
            analyze_ssl: Enable SSL certificate analysis
            use_system_dns: Use system default DNS instead of public DNS servers
        """
        self.wordlist = wordlist or COMMON_SUBDOMAINS
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.use_system_dns = use_system_dns
        # Use system DNS or provided/public DNS servers
        if use_system_dns:
            self.dns_servers = None  # Will use system default
        else:
            self.dns_servers = dns_servers or self.PUBLIC_DNS_SERVERS
        self.use_crtsh = use_crtsh
        self.analyze_ssl = analyze_ssl
        self.logger = get_logger()
        self._resolver: Optional[dns.asyncresolver.Resolver] = None

    def _get_resolver(self) -> dns.asyncresolver.Resolver:
        """Get or create the async DNS resolver."""
        if self._resolver is None:
            self._resolver = dns.asyncresolver.Resolver()
            # Only set custom nameservers if not using system DNS
            if self.dns_servers:
                self._resolver.nameservers = self.dns_servers
            # If dns_servers is None, it will use system default from /etc/resolv.conf
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

    async def discover_subdomains_crtsh(self, domain: str) -> Set[str]:
        """
        Discover subdomains using crt.sh certificate transparency logs.
        
        This is one of the most effective passive subdomain enumeration techniques
        as it finds subdomains from SSL/TLS certificates.

        Args:
            domain: Target domain

        Returns:
            Set of discovered subdomains
        """
        subdomains: Set[str] = set()
        
        self.logger.debug(f"Querying crt.sh for {domain} subdomains...")
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                url = f"https://crt.sh/?q=%.{domain}&output=json"
                response = await client.get(url)
                
                if response.status_code == 200:
                    try:
                        certs = response.json()
                        
                        for cert in certs:
                            # Extract name_value which contains domain names
                            name_value = cert.get("name_value", "")
                            
                            # Split by newlines (crt.sh can return multiple names)
                            for name in name_value.split("\n"):
                                name = name.strip().lower()
                                
                                # Skip wildcards and ensure it's a valid subdomain
                                if name.startswith("*."):
                                    name = name[2:]
                                
                                # Verify it's under our target domain
                                if name.endswith(f".{domain}") or name == domain:
                                    if name != domain:  # Don't add root domain
                                        subdomains.add(name)
                        
                        self.logger.info(f"crt.sh: Found {len(subdomains)} unique subdomains")
                        
                    except Exception as e:
                        self.logger.debug(f"crt.sh JSON parse error: {e}")
                else:
                    self.logger.debug(f"crt.sh returned status {response.status_code}")
                    
        except httpx.TimeoutException:
            self.logger.debug(f"crt.sh timeout for {domain}")
        except Exception as e:
            self.logger.debug(f"crt.sh error: {e}")
        
        return subdomains

    def get_ssl_cert_info(self, hostname: str, port: int = 443) -> Optional[SSLCertInfo]:
        """
        Retrieve and analyze SSL/TLS certificate information.
        
        Extracts certificate details including SAN domains which can reveal
        additional subdomains and related domains.

        Args:
            hostname: Target hostname
            port: HTTPS port (default: 443)

        Returns:
            SSLCertInfo object or None if failed
        """
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=5.0) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    
                    if not cert:
                        # Try to get binary cert and decode
                        cert_binary = ssock.getpeercert(binary_form=True)
                        if cert_binary:
                            return self._parse_binary_cert(cert_binary, hostname)
                        return None
                    
                    return self._parse_cert(cert, hostname)
                    
        except socket.timeout:
            self.logger.debug(f"SSL connection timeout for {hostname}")
        except ssl.SSLError as e:
            self.logger.debug(f"SSL error for {hostname}: {e}")
        except ConnectionRefusedError:
            self.logger.debug(f"Connection refused for {hostname}:443")
        except socket.gaierror:
            self.logger.debug(f"DNS resolution failed for {hostname}")
        except Exception as e:
            self.logger.debug(f"SSL cert retrieval error for {hostname}: {e}")
        
        return None

    def _parse_cert(self, cert: Dict, hostname: str) -> SSLCertInfo:
        """Parse a certificate dictionary into SSLCertInfo."""
        info = SSLCertInfo()
        
        # Extract subject
        subject_parts = []
        for item in cert.get("subject", ()):
            for key, value in item:
                if key == "commonName":
                    subject_parts.append(value)
        info.subject = ", ".join(subject_parts) if subject_parts else "Unknown"
        
        # Extract issuer
        issuer_parts = []
        for item in cert.get("issuer", ()):
            for key, value in item:
                if key in ("commonName", "organizationName"):
                    issuer_parts.append(value)
        info.issuer = ", ".join(issuer_parts) if issuer_parts else "Unknown"
        
        # Check if self-signed
        info.is_self_signed = info.subject == info.issuer
        
        # Extract validity dates
        not_before = cert.get("notBefore")
        not_after = cert.get("notAfter")
        
        if not_before:
            try:
                info.not_before = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
            except:
                pass
        
        if not_after:
            try:
                info.not_after = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                info.days_until_expiry = (info.not_after - datetime.now()).days
                info.is_expired = info.days_until_expiry < 0
            except:
                pass
        
        # Extract SAN (Subject Alternative Names)
        san_domains = []
        for san_type, san_value in cert.get("subjectAltName", ()):
            if san_type == "DNS":
                san_domains.append(san_value.lower())
        info.san_domains = list(set(san_domains))
        
        # Serial number
        info.serial_number = str(cert.get("serialNumber", ""))
        
        return info

    def _parse_binary_cert(self, cert_binary: bytes, hostname: str) -> Optional[SSLCertInfo]:
        """Parse a binary certificate (DER format)."""
        try:
            # Try using cryptography library if available
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            
            cert = x509.load_der_x509_certificate(cert_binary, default_backend())
            info = SSLCertInfo()
            
            # Subject
            info.subject = cert.subject.rfc4514_string()
            
            # Issuer
            info.issuer = cert.issuer.rfc4514_string()
            info.is_self_signed = info.subject == info.issuer
            
            # Validity
            info.not_before = cert.not_valid_before_utc.replace(tzinfo=None)
            info.not_after = cert.not_valid_after_utc.replace(tzinfo=None)
            info.days_until_expiry = (info.not_after - datetime.now()).days
            info.is_expired = info.days_until_expiry < 0
            
            # Serial number
            info.serial_number = format(cert.serial_number, 'x')
            
            # Signature algorithm
            info.signature_algorithm = cert.signature_algorithm_oid._name
            
            # SAN domains
            try:
                san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                info.san_domains = [
                    name.value.lower() 
                    for name in san_ext.value 
                    if isinstance(name, x509.DNSName)
                ]
            except x509.ExtensionNotFound:
                pass
            
            return info
            
        except ImportError:
            self.logger.debug("cryptography library not available for binary cert parsing")
        except Exception as e:
            self.logger.debug(f"Binary cert parse error: {e}")
        
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

        Combines crt.sh discovery, wordlist enumeration, DNS resolution,
        SSL analysis, and cloud provider detection.

        Args:
            target_domain: The target domain to scan

        Returns:
            List of discovered assets with IPs, CNAMEs, SSL info, and cloud info
        """
        self.logger.info(f"Starting infrastructure discovery on {target_domain}")
        discovered_assets: List[DiscoveredAsset] = []
        all_subdomains: Set[str] = set()

        # Phase 1: crt.sh subdomain discovery (passive)
        if self.use_crtsh:
            crtsh_subdomains = await self.discover_subdomains_crtsh(target_domain)
            all_subdomains.update(crtsh_subdomains)
            self.logger.debug(f"crt.sh found {len(crtsh_subdomains)} subdomains")

        # Phase 2: Add wordlist subdomains
        for sub in self.wordlist:
            all_subdomains.add(f"{sub}.{target_domain}")

        # First, resolve the root domain
        self.logger.debug(f"Resolving root domain: {target_domain}")
        root_asset = await self.resolve_dns(target_domain)
        if root_asset.is_alive:
            # Get SSL certificate for root domain
            if self.analyze_ssl:
                root_asset.ssl_cert = self.get_ssl_cert_info(target_domain)
                if root_asset.ssl_cert and root_asset.ssl_cert.san_domains:
                    # Add SAN domains to subdomain list
                    for san in root_asset.ssl_cert.san_domains:
                        if san.endswith(f".{target_domain}") and san != target_domain:
                            all_subdomains.add(san)
                    self.logger.debug(
                        f"SSL SAN added {len(root_asset.ssl_cert.san_domains)} domains"
                    )
            
            discovered_assets.append(root_asset)
            self.logger.info(
                f"Root domain resolved: {target_domain} -> {root_asset.ips}"
            )

        # Phase 3: Enumerate all discovered subdomains
        self.logger.info(f"Enumerating {len(all_subdomains)} potential subdomains...")
        
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def resolve_subdomain(hostname: str) -> Optional[DiscoveredAsset]:
            async with semaphore:
                asset = await self.resolve_dns(hostname)
                if asset.is_alive:
                    self.logger.debug(f"Found: {hostname} -> {asset.ips}")
                    return asset
                return None

        tasks = [resolve_subdomain(sub) for sub in all_subdomains]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, DiscoveredAsset) and result.is_alive:
                # Check if already discovered (by hostname)
                existing = next(
                    (a for a in discovered_assets if a.hostname == result.hostname),
                    None
                )
                if not existing:
                    discovered_assets.append(result)
            elif isinstance(result, Exception):
                self.logger.debug(f"Subdomain enumeration error: {result}")

        # Phase 4: SSL analysis for discovered assets (optional, limited)
        if self.analyze_ssl:
            ssl_analyzed = 0
            for asset in discovered_assets[:20]:  # Limit to avoid slowdown
                if asset.ssl_cert is None and asset.hostname != target_domain:
                    asset.ssl_cert = self.get_ssl_cert_info(asset.hostname)
                    if asset.ssl_cert:
                        ssl_analyzed += 1
            
            if ssl_analyzed:
                self.logger.debug(f"Analyzed SSL certs for {ssl_analyzed} assets")

        # Summary
        alive_count = len(discovered_assets)
        cloud_count = sum(1 for a in discovered_assets if a.cloud_providers)
        ssl_count = sum(1 for a in discovered_assets if a.ssl_cert)
        
        self.logger.info(
            f"Discovery complete: {alive_count} assets found, "
            f"{cloud_count} cloud-hosted, {ssl_count} with SSL analyzed"
        )

        return discovered_assets
