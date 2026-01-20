"""
Port Intelligence Module for RedSurface.

Uses Shodan API to enrich IP addresses with port, service, and vulnerability data.
NO active scanning - purely passive API lookups.
"""

import asyncio
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any
import time

import httpx

from utils.logger import get_logger


@dataclass
class HostIntel:
    """Intelligence data for a single host/IP."""
    
    ip: str
    ports: List[int] = field(default_factory=list)
    os: Optional[str] = None
    hostnames: List[str] = field(default_factory=list)
    vulns: List[str] = field(default_factory=list)
    services: List[Dict[str, Any]] = field(default_factory=list)
    org: Optional[str] = None
    isp: Optional[str] = None
    asn: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    last_update: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    raw_data: Optional[Dict] = None
    
    def to_dict(self) -> dict:
        """Export host intel to dictionary."""
        return {
            "ip": self.ip,
            "ports": self.ports,
            "os": self.os,
            "hostnames": self.hostnames,
            "vulns": self.vulns,
            "services": self.services,
            "org": self.org,
            "isp": self.isp,
            "asn": self.asn,
            "country": self.country,
            "city": self.city,
            "last_update": self.last_update,
            "tags": self.tags,
        }


@dataclass
class PortIntelResults:
    """Aggregated results from port intelligence gathering."""
    
    hosts: Dict[str, HostIntel] = field(default_factory=dict)
    total_ports: int = 0
    total_vulns: int = 0
    queries_made: int = 0
    queries_failed: int = 0
    
    def to_dict(self) -> dict:
        """Export results to dictionary."""
        return {
            "summary": {
                "hosts_queried": len(self.hosts),
                "total_ports": self.total_ports,
                "total_vulns": self.total_vulns,
                "queries_made": self.queries_made,
                "queries_failed": self.queries_failed,
            },
            "hosts": {ip: host.to_dict() for ip, host in self.hosts.items()},
        }


class PortIntel:
    """
    Port Intelligence module using Shodan API.
    
    Enriches IP addresses with port, service, OS, and vulnerability data
    without sending any packets to the target (passive reconnaissance).
    """
    
    SHODAN_API_BASE = "https://api.shodan.io"
    
    def __init__(
        self,
        shodan_api_key: Optional[str] = None,
        rate_limit_delay: float = 1.0,
        timeout: float = 15.0,
    ):
        """
        Initialize PortIntel module.
        
        Args:
            shodan_api_key: Shodan API key (required for queries)
            rate_limit_delay: Delay between API requests (seconds)
            timeout: HTTP request timeout
        """
        self.api_key = shodan_api_key
        self.rate_limit_delay = rate_limit_delay
        self.timeout = timeout
        self.logger = get_logger()
        self.results = PortIntelResults()
        self._last_request_time = 0.0
        
        # Try to use official shodan library if available
        self._shodan_client = None
        if self.api_key:
            try:
                import shodan
                self._shodan_client = shodan.Shodan(self.api_key)
                self.logger.debug("Using official Shodan library")
            except ImportError:
                self.logger.debug("Shodan library not installed, using direct API")
    
    def _rate_limit(self) -> None:
        """Enforce rate limiting between requests."""
        elapsed = time.time() - self._last_request_time
        if elapsed < self.rate_limit_delay:
            sleep_time = self.rate_limit_delay - elapsed
            time.sleep(sleep_time)
        self._last_request_time = time.time()
    
    def query_ip(self, ip_address: str) -> Optional[HostIntel]:
        """
        Query Shodan API for information about an IP address.
        
        Args:
            ip_address: IP address to query
            
        Returns:
            HostIntel object with gathered data, or None if query failed
        """
        if not self.api_key:
            self.logger.warning("Shodan API key not configured, skipping port intel")
            return None
        
        self.logger.debug(f"Querying Shodan for {ip_address}")
        self._rate_limit()
        self.results.queries_made += 1
        
        try:
            # Try official library first
            if self._shodan_client:
                return self._query_with_library(ip_address)
            else:
                return self._query_with_api(ip_address)
                
        except Exception as e:
            self.logger.debug(f"Shodan query failed for {ip_address}: {e}")
            self.results.queries_failed += 1
            return None
    
    def _query_with_library(self, ip_address: str) -> Optional[HostIntel]:
        """Query using official Shodan library."""
        try:
            data = self._shodan_client.host(ip_address)
            return self._parse_shodan_response(ip_address, data)
        except Exception as e:
            error_msg = str(e).lower()
            if "no information available" in error_msg:
                self.logger.debug(f"No Shodan data for {ip_address}")
            else:
                self.logger.debug(f"Shodan library error for {ip_address}: {e}")
            self.results.queries_failed += 1
            return None
    
    def _query_with_api(self, ip_address: str) -> Optional[HostIntel]:
        """Query using direct API requests."""
        url = f"{self.SHODAN_API_BASE}/shodan/host/{ip_address}"
        params = {"key": self.api_key}
        
        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.get(url, params=params)
                
                if response.status_code == 200:
                    data = response.json()
                    return self._parse_shodan_response(ip_address, data)
                elif response.status_code == 404:
                    self.logger.debug(f"No Shodan data for {ip_address}")
                    self.results.queries_failed += 1
                    return None
                elif response.status_code == 401:
                    self.logger.error("Invalid Shodan API key")
                    self.results.queries_failed += 1
                    return None
                elif response.status_code == 403:
                    self.logger.warning(f"Shodan API 403 for {ip_address} - API key may have no query credits (free tier)")
                    self.results.queries_failed += 1
                    return None
                elif response.status_code == 429:
                    self.logger.warning("Shodan rate limit exceeded, waiting...")
                    time.sleep(5)  # Extra wait on rate limit
                    self.results.queries_failed += 1
                    return None
                else:
                    self.logger.debug(
                        f"Shodan API error for {ip_address}: {response.status_code}"
                    )
                    self.results.queries_failed += 1
                    return None
                    
        except httpx.TimeoutException:
            self.logger.debug(f"Shodan API timeout for {ip_address}")
            self.results.queries_failed += 1
            return None
        except httpx.RequestError as e:
            self.logger.debug(f"Shodan API request error for {ip_address}: {e}")
            self.results.queries_failed += 1
            return None
    
    def _parse_shodan_response(self, ip_address: str, data: dict) -> HostIntel:
        """
        Parse Shodan API response into HostIntel object.
        
        Args:
            ip_address: The queried IP
            data: Raw Shodan API response
            
        Returns:
            Populated HostIntel object
        """
        # Extract ports from service data
        ports = data.get("ports", [])
        
        # Extract services with details
        services = []
        for item in data.get("data", []):
            service_info = {
                "port": item.get("port"),
                "protocol": item.get("transport", "tcp"),
                "service": item.get("product", item.get("_shodan", {}).get("module", "unknown")),
                "version": item.get("version"),
                "banner": item.get("data", "")[:500] if item.get("data") else None,  # Truncate banner
                "ssl": bool(item.get("ssl")),
            }
            
            # Extract SSL certificate info if present
            if item.get("ssl"):
                ssl_info = item.get("ssl", {})
                cert = ssl_info.get("cert", {})
                service_info["ssl_info"] = {
                    "issuer": cert.get("issuer", {}).get("O"),
                    "subject": cert.get("subject", {}).get("CN"),
                    "expires": cert.get("expires"),
                }
            
            # Extract HTTP info if present
            if item.get("http"):
                http_info = item.get("http", {})
                service_info["http"] = {
                    "title": http_info.get("title"),
                    "server": http_info.get("server"),
                    "status": http_info.get("status"),
                }
            
            services.append(service_info)
        
        # Extract vulnerabilities
        vulns = list(data.get("vulns", {}).keys()) if data.get("vulns") else []
        
        # Build HostIntel object
        host_intel = HostIntel(
            ip=ip_address,
            ports=sorted(ports),
            os=data.get("os"),
            hostnames=data.get("hostnames", []),
            vulns=vulns,
            services=services,
            org=data.get("org"),
            isp=data.get("isp"),
            asn=data.get("asn"),
            country=data.get("country_name"),
            city=data.get("city"),
            last_update=data.get("last_update"),
            tags=data.get("tags", []),
            raw_data=data,
        )
        
        # Update totals
        self.results.total_ports += len(ports)
        self.results.total_vulns += len(vulns)
        
        return host_intel
    
    async def query_ip_async(self, ip_address: str) -> Optional[HostIntel]:
        """
        Async wrapper for query_ip (runs in thread pool).
        
        Args:
            ip_address: IP address to query
            
        Returns:
            HostIntel object or None
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.query_ip, ip_address)
    
    def run(self, target) -> PortIntelResults:
        """
        Run port intelligence gathering for all discovered IPs.
        
        Args:
            target: Target object with discovered IPs (target.ips)
            
        Returns:
            PortIntelResults with all gathered intelligence
        """
        if not self.api_key:
            self.logger.warning("[Port Intel] Skipped - no Shodan API key configured")
            return self.results
        
        # Get unique IPs from target
        ips_to_query: Set[str] = set()
        
        if hasattr(target, "ips") and target.ips:
            ips_to_query.update(target.ips)
        
        # Also check for IPs in services dict if available
        if hasattr(target, "services") and target.services:
            ips_to_query.update(target.services.keys())
        
        if not ips_to_query:
            self.logger.info("[Port Intel] No IPs to query")
            return self.results
        
        self.logger.info("=" * 50)
        self.logger.info(f"[Port Intel] Querying Shodan for {len(ips_to_query)} IPs")
        self.logger.info("=" * 50)
        
        # Query each IP with rate limiting
        for idx, ip in enumerate(sorted(ips_to_query), 1):
            self.logger.info(f"  [{idx}/{len(ips_to_query)}] Querying {ip}...")
            
            host_intel = self.query_ip(ip)
            
            if host_intel:
                self.results.hosts[ip] = host_intel
                self.logger.info(
                    f"    Found: {len(host_intel.ports)} ports, "
                    f"{len(host_intel.vulns)} vulns, "
                    f"OS: {host_intel.os or 'unknown'}"
                )
                
                # Update target with port data
                self._update_target(target, host_intel)
            else:
                self.logger.debug(f"    No data for {ip}")
        
        # Summary
        self.logger.info("=" * 50)
        self.logger.info("[Port Intel] Complete")
        self.logger.info(f"  Hosts with data: {len(self.results.hosts)}")
        self.logger.info(f"  Total ports: {self.results.total_ports}")
        self.logger.info(f"  Total vulns: {self.results.total_vulns}")
        self.logger.info(f"  Queries: {self.results.queries_made} made, {self.results.queries_failed} failed")
        self.logger.info("=" * 50)
        
        return self.results
    
    async def run_async(self, target) -> PortIntelResults:
        """
        Async version of run (still rate-limited sequentially).
        
        Args:
            target: Target object with discovered IPs
            
        Returns:
            PortIntelResults with all gathered intelligence
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.run, target)
    
    def _update_target(self, target, host_intel: HostIntel) -> None:
        """
        Update Target object with port intelligence data.
        
        Args:
            target: Target object to update
            host_intel: HostIntel data to add
        """
        ip = host_intel.ip
        
        # Initialize services dict if needed
        if not hasattr(target, "services") or target.services is None:
            target.services = {}
        
        # Add/update services for this IP
        if ip not in target.services:
            target.services[ip] = []
        
        for service in host_intel.services:
            service_entry = {
                "port": service.get("port"),
                "protocol": service.get("protocol", "tcp"),
                "service": service.get("service"),
                "version": service.get("version"),
                "source": "shodan",
            }
            
            # Check if this port already exists
            existing_ports = [s.get("port") for s in target.services[ip]]
            if service.get("port") not in existing_ports:
                target.services[ip].append(service_entry)
        
        # Add hostnames to subdomains if not already present
        if hasattr(target, "subdomains"):
            for hostname in host_intel.hostnames:
                if hostname.endswith(target.domain):
                    target.subdomains.add(hostname)
        
        # Store Shodan vulnerabilities
        if not hasattr(target, "shodan_vulns") or target.shodan_vulns is None:
            target.shodan_vulns = {}
        
        if host_intel.vulns:
            target.shodan_vulns[ip] = host_intel.vulns
        
        # Store port intel results reference
        if not hasattr(target, "port_intel") or target.port_intel is None:
            target.port_intel = {}
        
        target.port_intel[ip] = host_intel.to_dict()
