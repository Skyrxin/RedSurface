"""
Central Target class to hold reconnaissance state.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Set, Optional, Union
from datetime import datetime
from pathlib import Path


@dataclass
class Target:
    """
    Central state holder for a reconnaissance target.
    
    Attributes:
        domain: The root target domain
        subdomains: Discovered subdomains
        ips: Resolved IP addresses mapped to hostnames
        technologies: Fingerprinted technologies per host
        cloud_services: Detected cloud services
        vulnerabilities: Discovered CVEs mapped to technologies
        emails: Discovered email addresses
        people: Discovered people/employees
        scan_start: Timestamp when scan started
        scan_end: Timestamp when scan completed
    """
    domain: str
    subdomains: Set[str] = field(default_factory=set)
    ips: Dict[str, List[str]] = field(default_factory=dict)  # hostname -> [IPs]
    technologies: Dict[str, List[str]] = field(default_factory=dict)  # host -> [techs]
    cloud_services: Dict[str, str] = field(default_factory=dict)  # IP -> cloud provider
    vulnerabilities: Dict[str, List[str]] = field(default_factory=dict)  # tech -> [CVEs]
    emails: Set[str] = field(default_factory=set)  # discovered emails
    people: List[Dict[str, Any]] = field(default_factory=list)  # discovered people
    discovered_directories: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)  # host -> [dirs]
    port_intel: Dict[str, Dict[str, Any]] = field(default_factory=dict)  # IP -> port intel data
    scan_start: Optional[datetime] = None
    scan_end: Optional[datetime] = None
    
    # Enhanced data fields
    ssl_certificates: Dict[str, Dict[str, Any]] = field(default_factory=dict)  # hostname -> SSL cert info
    technology_details: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)  # host -> [full tech details]
    infrastructure_assets: Dict[str, Dict[str, Any]] = field(default_factory=dict)  # hostname -> asset details
    active_recon_results: Dict[str, Any] = field(default_factory=dict)  # zone transfer, etc.
    dns_records: Dict[str, Dict[str, List[str]]] = field(default_factory=dict)  # hostname -> {A: [], CNAME: [], etc.}
    scan_config_used: Dict[str, Any] = field(default_factory=dict)  # scan configuration used
    http_responses: Dict[str, Dict[str, Any]] = field(default_factory=dict)  # hostname -> HTTP response info

    def __post_init__(self) -> None:
        """Normalize domain on initialization."""
        self.domain = self._normalize_domain(self.domain)

    @staticmethod
    def _normalize_domain(domain: str) -> str:
        """Normalize a domain string."""
        domain = domain.lower().strip()
        if domain.startswith(("http://", "https://")):
            domain = domain.split("://")[1].split("/")[0]
        return domain

    @classmethod
    def from_domains(cls, domains: List[str]) -> List["Target"]:
        """
        Create multiple Target instances from a list of domains (Bulk Scan support).
        
        Args:
            domains: List of domain strings
            
        Returns:
            List of Target instances
        """
        targets = []
        for domain in domains:
            domain = domain.strip()
            if domain and not domain.startswith("#"):  # Skip empty lines and comments
                targets.append(cls(domain=domain))
        return targets

    @classmethod
    def from_file(cls, filepath: Union[str, Path]) -> List["Target"]:
        """
        Create multiple Target instances from a file containing domains (Bulk Scan support).
        
        Args:
            filepath: Path to file containing one domain per line
            
        Returns:
            List of Target instances
            
        Raises:
            FileNotFoundError: If the file doesn't exist
            ValueError: If the file is empty or contains no valid domains
        """
        filepath = Path(filepath)
        if not filepath.exists():
            raise FileNotFoundError(f"Input file not found: {filepath}")
        
        with open(filepath, "r", encoding="utf-8") as f:
            domains = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        
        if not domains:
            raise ValueError(f"No valid domains found in: {filepath}")
        
        return cls.from_domains(domains)

    def start_scan(self) -> None:
        """Mark the scan as started."""
        self.scan_start = datetime.now()

    def end_scan(self) -> None:
        """Mark the scan as completed."""
        self.scan_end = datetime.now()

    @property
    def scan_duration(self) -> Optional[float]:
        """Return scan duration in seconds."""
        if self.scan_start and self.scan_end:
            return (self.scan_end - self.scan_start).total_seconds()
        return None

    def add_subdomain(self, subdomain: str) -> None:
        """Add a discovered subdomain."""
        self.subdomains.add(subdomain.lower().strip())

    def add_ip(self, hostname: str, ip: str) -> None:
        """Map an IP address to a hostname."""
        hostname = hostname.lower().strip()
        if hostname not in self.ips:
            self.ips[hostname] = []
        if ip not in self.ips[hostname]:
            self.ips[hostname].append(ip)

    def add_technology(self, host: str, tech: str) -> None:
        """Add a fingerprinted technology to a host."""
        host = host.lower().strip()
        if host not in self.technologies:
            self.technologies[host] = []
        if tech not in self.technologies[host]:
            self.technologies[host].append(tech)

    def add_cloud_service(self, ip: str, provider: str) -> None:
        """Associate an IP with a cloud provider."""
        self.cloud_services[ip] = provider

    def add_vulnerability(self, tech: str, cve: str) -> None:
        """Add a CVE to a technology."""
        if tech not in self.vulnerabilities:
            self.vulnerabilities[tech] = []
        if cve not in self.vulnerabilities[tech]:
            self.vulnerabilities[tech].append(cve)

    def add_email(self, email: str) -> None:
        """Add a discovered email address."""
        self.emails.add(email.lower().strip())

    def add_person(self, person_data: Dict[str, Any]) -> None:
        """Add a discovered person/employee."""
        self.people.append(person_data)

    def add_directory(self, host: str, dir_info: Dict[str, Any]) -> None:
        """Add a discovered directory/file to a host."""
        host = host.lower().strip()
        if host not in self.discovered_directories:
            self.discovered_directories[host] = []
        self.discovered_directories[host].append(dir_info)

    def add_port_intel(self, ip: str, intel_data: Dict[str, Any]) -> None:
        """Add port intelligence data for an IP address."""
        self.port_intel[ip] = intel_data

    def add_ssl_certificate(self, hostname: str, cert_info: Dict[str, Any]) -> None:
        """Add SSL certificate information for a hostname."""
        self.ssl_certificates[hostname.lower().strip()] = cert_info

    def add_technology_detail(self, host: str, tech_detail: Dict[str, Any]) -> None:
        """Add detailed technology fingerprint to a host."""
        host = host.lower().strip()
        if host not in self.technology_details:
            self.technology_details[host] = []
        self.technology_details[host].append(tech_detail)

    def add_infrastructure_asset(self, hostname: str, asset_data: Dict[str, Any]) -> None:
        """Add infrastructure asset details."""
        self.infrastructure_assets[hostname.lower().strip()] = asset_data

    def set_active_recon_results(self, results: Dict[str, Any]) -> None:
        """Set active reconnaissance results (zone transfer, etc.)."""
        self.active_recon_results = results

    def add_dns_records(self, hostname: str, record_type: str, records: List[str]) -> None:
        """Add DNS records for a hostname."""
        hostname = hostname.lower().strip()
        if hostname not in self.dns_records:
            self.dns_records[hostname] = {}
        self.dns_records[hostname][record_type] = records

    def set_scan_config(self, config_dict: Dict[str, Any]) -> None:
        """Store the scan configuration used."""
        self.scan_config_used = config_dict

    def add_http_response(self, hostname: str, response_info: Dict[str, Any]) -> None:
        """Add HTTP response information for a hostname."""
        self.http_responses[hostname.lower().strip()] = response_info

    def to_dict(self) -> dict:
        """Export target state to dictionary with all collected data."""
        return {
            "meta": {
                "domain": self.domain,
                "scan_start": self.scan_start.isoformat() if self.scan_start else None,
                "scan_end": self.scan_end.isoformat() if self.scan_end else None,
                "scan_duration_seconds": self.scan_duration,
                "scan_config": self.scan_config_used,
            },
            "summary": {
                "subdomains_count": len(self.subdomains),
                "ips_count": len(set(ip for ips in self.ips.values() for ip in ips)),
                "technologies_count": sum(len(t) for t in self.technologies.values()),
                "vulnerabilities_count": sum(len(v) for v in self.vulnerabilities.values()),
                "emails_count": len(self.emails),
                "people_count": len(self.people),
                "directories_count": sum(len(d) for d in self.discovered_directories.values()),
                "ports_count": sum(len(h.get("ports", [])) for h in self.port_intel.values()),
                "cloud_services_count": len(self.cloud_services),
            },
            "domain": self.domain,
            "subdomains": sorted(list(self.subdomains)),
            "infrastructure": {
                "ip_mappings": self.ips,
                "dns_records": self.dns_records,
                "ssl_certificates": self.ssl_certificates,
                "assets": self.infrastructure_assets,
                "cloud_services": self.cloud_services,
            },
            "fingerprinting": {
                "technologies": self.technologies,
                "technology_details": self.technology_details,
                "vulnerabilities": self.vulnerabilities,
            },
            "osint": {
                "emails": sorted(list(self.emails)),
                "people": self.people,
            },
            "active_recon": {
                "zone_transfer": self.active_recon_results.get("zone_transfer", {}),
                "directory_enumeration": self.discovered_directories,
            },
            "port_intelligence": self.port_intel,
            "http_responses": self.http_responses,
        }
