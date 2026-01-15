"""
Technology Fingerprinting Module for RedSurface.
Analyzes HTTP headers and responses to identify technologies and map CVEs.
"""

import asyncio
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
import httpx

from utils.logger import get_logger


# Technology signatures for header matching
HEADER_SIGNATURES: Dict[str, Dict[str, List[Tuple[str, str]]]] = {
    # Server header patterns
    "Server": [
        (r"nginx/?(\d+\.\d+\.?\d*)?", "Nginx"),
        (r"Apache/?(\d+\.\d+\.?\d*)?", "Apache"),
        (r"Microsoft-IIS/?(\d+\.?\d*)?", "Microsoft IIS"),
        (r"LiteSpeed", "LiteSpeed"),
        (r"cloudflare", "Cloudflare"),
        (r"AmazonS3", "Amazon S3"),
        (r"gunicorn/?(\d+\.\d+\.?\d*)?", "Gunicorn"),
        (r"Werkzeug/?(\d+\.\d+\.?\d*)?", "Werkzeug"),
        (r"openresty/?(\d+\.\d+\.?\d*)?", "OpenResty"),
        (r"Cowboy", "Cowboy"),
        (r"Caddy", "Caddy"),
        (r"Kestrel", "Kestrel"),
        (r"Jetty", "Jetty"),
        (r"Tomcat", "Apache Tomcat"),
        (r"WEBrick/?(\d+\.\d+\.?\d*)?", "WEBrick"),
    ],
    # X-Powered-By header patterns
    "X-Powered-By": [
        (r"PHP/?(\d+\.\d+\.?\d*)?", "PHP"),
        (r"ASP\.NET", "ASP.NET"),
        (r"Express", "Express.js"),
        (r"Next\.js", "Next.js"),
        (r"Phusion Passenger", "Phusion Passenger"),
        (r"PleskLin", "Plesk"),
        (r"JSF/?(\d+\.?\d*)?", "JavaServer Faces"),
        (r"Servlet/?(\d+\.?\d*)?", "Java Servlet"),
        (r"Ruby", "Ruby"),
        (r"Python", "Python"),
        (r"Flask", "Flask"),
        (r"Django", "Django"),
        (r"Laravel", "Laravel"),
        (r"Symfony", "Symfony"),
        (r"CakePHP", "CakePHP"),
        (r"CodeIgniter", "CodeIgniter"),
    ],
    # X-AspNet-Version header
    "X-AspNet-Version": [
        (r"(\d+\.\d+\.?\d*)", "ASP.NET"),
    ],
    # X-AspNetMvc-Version header
    "X-AspNetMvc-Version": [
        (r"(\d+\.?\d*)", "ASP.NET MVC"),
    ],
    # X-Generator header
    "X-Generator": [
        (r"Drupal", "Drupal"),
        (r"WordPress", "WordPress"),
        (r"Joomla", "Joomla"),
    ],
}

# Cookie-based technology detection
COOKIE_SIGNATURES: List[Tuple[str, str]] = [
    (r"PHPSESSID", "PHP"),
    (r"JSESSIONID", "Java"),
    (r"ASP\.NET_SessionId", "ASP.NET"),
    (r"_rails_session", "Ruby on Rails"),
    (r"laravel_session", "Laravel"),
    (r"ci_session", "CodeIgniter"),
    (r"CFID|CFTOKEN", "ColdFusion"),
    (r"connect\.sid", "Express.js"),
    (r"__cfduid|cf_clearance", "Cloudflare"),
    (r"wp-settings", "WordPress"),
    (r"drupal", "Drupal"),
]

# Mock CVE database for vulnerable technologies
MOCK_CVE_DATABASE: Dict[str, Dict] = {
    "PHP 5": {
        "cve_id": "CVE-2019-11043",
        "severity": "High",
        "cvss_score": 9.8,
        "description": "PHP-FPM Remote Code Execution vulnerability in PHP 5.x",
        "recommendation": "Upgrade to PHP 7.4+ or PHP 8.x",
    },
    "PHP 7.0": {
        "cve_id": "CVE-2019-11043",
        "severity": "High",
        "cvss_score": 9.8,
        "description": "PHP-FPM Remote Code Execution vulnerability",
        "recommendation": "Upgrade to PHP 7.4.2+ or PHP 8.x",
    },
    "Old-Jenkins": {
        "cve_id": "CVE-2024-23897",
        "severity": "Critical",
        "cvss_score": 9.8,
        "description": "Jenkins arbitrary file read vulnerability via CLI",
        "recommendation": "Update Jenkins to 2.442+ or LTS 2.426.3+",
    },
    "Apache 2.4.49": {
        "cve_id": "CVE-2021-41773",
        "severity": "Critical",
        "cvss_score": 9.8,
        "description": "Path traversal and RCE in Apache HTTP Server 2.4.49",
        "recommendation": "Upgrade to Apache 2.4.51+",
    },
    "Apache 2.4.50": {
        "cve_id": "CVE-2021-42013",
        "severity": "Critical",
        "cvss_score": 9.8,
        "description": "Path traversal and RCE in Apache HTTP Server 2.4.50",
        "recommendation": "Upgrade to Apache 2.4.51+",
    },
    "Microsoft IIS 6": {
        "cve_id": "CVE-2017-7269",
        "severity": "Critical",
        "cvss_score": 9.8,
        "description": "Buffer overflow in WebDAV service in IIS 6.0",
        "recommendation": "Upgrade to IIS 10+",
    },
    "nginx 1.16": {
        "cve_id": "CVE-2019-20372",
        "severity": "Medium",
        "cvss_score": 5.3,
        "description": "HTTP request smuggling in nginx 1.16.x",
        "recommendation": "Upgrade to nginx 1.17.7+",
    },
    "WordPress": {
        "cve_id": "CVE-2023-2982",
        "severity": "High",
        "cvss_score": 8.8,
        "description": "WordPress authentication bypass vulnerability",
        "recommendation": "Update WordPress to latest version",
    },
    "Drupal": {
        "cve_id": "CVE-2018-7600",
        "severity": "Critical",
        "cvss_score": 9.8,
        "description": "Drupalgeddon2 - Remote Code Execution",
        "recommendation": "Update Drupal to 7.58+ or 8.5.1+",
    },
}


@dataclass
class TechFingerprint:
    """Represents a fingerprinted technology."""

    name: str
    version: Optional[str] = None
    source: str = "header"  # header, cookie, body
    confidence: str = "high"  # high, medium, low
    cves: List[Dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert to dictionary representation."""
        return {
            "name": self.name,
            "version": self.version,
            "full_name": f"{self.name} {self.version}" if self.version else self.name,
            "source": self.source,
            "confidence": self.confidence,
            "cves": self.cves,
        }


class TechFingerprinter:
    """
    Fingerprints technologies from HTTP responses.

    Features:
        - Header analysis (Server, X-Powered-By, etc.)
        - Cookie-based detection
        - Version extraction
        - CVE mapping (mock database)
    """

    def __init__(
        self,
        timeout: float = 10.0,
        max_concurrent: int = 20,
        follow_redirects: bool = True,
        verify_ssl: bool = False,
    ) -> None:
        """
        Initialize the tech fingerprinter.

        Args:
            timeout: HTTP request timeout in seconds
            max_concurrent: Maximum concurrent HTTP requests
            follow_redirects: Whether to follow HTTP redirects
            verify_ssl: Whether to verify SSL certificates
        """
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.follow_redirects = follow_redirects
        self.verify_ssl = verify_ssl
        self.logger = get_logger()

    async def analyze_headers(
        self,
        url: str,
    ) -> Tuple[Optional[httpx.Headers], Optional[str]]:
        """
        Fetch HTTP headers from a URL.

        Args:
            url: The URL to analyze

        Returns:
            Tuple of (headers, cookies_string) or (None, None) on error
        """
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=self.follow_redirects,
                verify=self.verify_ssl,
            ) as client:
                response = await client.get(url)
                
                # Extract Set-Cookie headers
                cookies = response.headers.get_list("set-cookie")
                cookies_str = "; ".join(cookies) if cookies else None
                
                self.logger.debug(f"Fetched headers from {url} (status: {response.status_code})")
                return response.headers, cookies_str

        except httpx.TimeoutException:
            self.logger.debug(f"Timeout fetching {url}")
            return None, None
        except httpx.ConnectError as e:
            self.logger.debug(f"Connection error for {url}: {e}")
            return None, None
        except httpx.HTTPError as e:
            self.logger.debug(f"HTTP error for {url}: {e}")
            return None, None
        except Exception as e:
            self.logger.debug(f"Unexpected error for {url}: {e}")
            return None, None

    def match_tech(
        self,
        headers: httpx.Headers,
        cookies: Optional[str] = None,
    ) -> List[TechFingerprint]:
        """
        Match technologies from HTTP headers and cookies.

        Args:
            headers: HTTP response headers
            cookies: Cookie string from Set-Cookie headers

        Returns:
            List of identified TechFingerprint objects
        """
        detected: Dict[str, TechFingerprint] = {}

        # Analyze headers
        for header_name, patterns in HEADER_SIGNATURES.items():
            header_value = headers.get(header_name, "")
            if not header_value:
                continue

            for pattern, tech_name in patterns:
                match = re.search(pattern, header_value, re.IGNORECASE)
                if match:
                    version = None
                    if match.groups():
                        version = match.group(1) if match.group(1) else None

                    key = f"{tech_name}_{version or 'unknown'}"
                    if key not in detected:
                        detected[key] = TechFingerprint(
                            name=tech_name,
                            version=version,
                            source="header",
                            confidence="high",
                        )
                        self.logger.debug(
                            f"Detected {tech_name}"
                            + (f" {version}" if version else "")
                            + f" from {header_name} header"
                        )

        # Analyze cookies
        if cookies:
            for pattern, tech_name in COOKIE_SIGNATURES:
                if re.search(pattern, cookies, re.IGNORECASE):
                    key = f"{tech_name}_cookie"
                    if key not in detected:
                        detected[key] = TechFingerprint(
                            name=tech_name,
                            version=None,
                            source="cookie",
                            confidence="medium",
                        )
                        self.logger.debug(f"Detected {tech_name} from cookie")

        return list(detected.values())

    def get_mock_cve(self, tech_name: str, version: Optional[str] = None) -> Optional[Dict]:
        """
        Get mock CVE data for a technology.

        Args:
            tech_name: Name of the technology
            version: Optional version string

        Returns:
            CVE dictionary if vulnerable, None otherwise
        """
        # Check exact match with version
        if version:
            full_name = f"{tech_name} {version}"
            if full_name in MOCK_CVE_DATABASE:
                return MOCK_CVE_DATABASE[full_name]
            
            # Check version prefix (e.g., "PHP 5.6" matches "PHP 5")
            for key, cve_data in MOCK_CVE_DATABASE.items():
                if key.startswith(tech_name) and version.startswith(key.split()[-1] if " " in key else ""):
                    return cve_data

        # Check technology name only
        if tech_name in MOCK_CVE_DATABASE:
            return MOCK_CVE_DATABASE[tech_name]

        # Special patterns
        if tech_name == "PHP" and version:
            major_version = version.split(".")[0] if version else None
            if major_version in ("5", "7.0"):
                return MOCK_CVE_DATABASE.get(f"PHP {major_version}")

        return None

    async def fingerprint_host(
        self,
        hostname: str,
        ports: Optional[List[int]] = None,
    ) -> List[TechFingerprint]:
        """
        Fingerprint technologies on a host.

        Args:
            hostname: Hostname to fingerprint
            ports: Optional list of ports to check (default: [80, 443])

        Returns:
            List of detected TechFingerprint objects
        """
        ports = ports or [443, 80]
        all_fingerprints: Dict[str, TechFingerprint] = {}

        for port in ports:
            scheme = "https" if port == 443 else "http"
            url = f"{scheme}://{hostname}:{port}" if port not in (80, 443) else f"{scheme}://{hostname}"

            headers, cookies = await self.analyze_headers(url)
            if headers is None:
                continue

            fingerprints = self.match_tech(headers, cookies)
            
            # Add CVE data and deduplicate
            for fp in fingerprints:
                cve = self.get_mock_cve(fp.name, fp.version)
                if cve:
                    fp.cves.append(cve)
                    self.logger.warning(
                        f"Potential vulnerability: {fp.name} "
                        f"-> {cve['cve_id']} ({cve['severity']})"
                    )
                
                key = f"{fp.name}_{fp.version or 'unknown'}"
                if key not in all_fingerprints:
                    all_fingerprints[key] = fp

        return list(all_fingerprints.values())

    async def run(
        self,
        hostnames: List[str],
    ) -> Dict[str, List[TechFingerprint]]:
        """
        Run fingerprinting on multiple hosts.

        Args:
            hostnames: List of hostnames to fingerprint

        Returns:
            Dictionary mapping hostname to list of TechFingerprints
        """
        self.logger.info(f"Starting technology fingerprinting on {len(hostnames)} hosts")
        
        results: Dict[str, List[TechFingerprint]] = {}
        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def fingerprint_with_limit(host: str) -> Tuple[str, List[TechFingerprint]]:
            async with semaphore:
                fingerprints = await self.fingerprint_host(host)
                return host, fingerprints

        tasks = [fingerprint_with_limit(host) for host in hostnames]
        completed = await asyncio.gather(*tasks, return_exceptions=True)

        for result in completed:
            if isinstance(result, Exception):
                self.logger.debug(f"Fingerprinting error: {result}")
                continue
            hostname, fingerprints = result
            if fingerprints:
                results[hostname] = fingerprints
                self.logger.info(
                    f"{hostname}: {len(fingerprints)} technologies detected"
                )

        # Summary
        total_techs = sum(len(fps) for fps in results.values())
        total_cves = sum(
            len(fp.cves) for fps in results.values() for fp in fps
        )
        
        self.logger.info(
            f"Fingerprinting complete: {total_techs} technologies, "
            f"{total_cves} potential vulnerabilities"
        )

        return results
