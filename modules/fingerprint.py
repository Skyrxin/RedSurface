"""
Technology Fingerprinting Module for RedSurface.
Analyzes HTTP headers, HTML content, and JavaScript to identify technologies.
Includes real NVD CVE lookup for vulnerability mapping.
"""

import asyncio
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import quote
import httpx

from utils.logger import get_logger


# NVD API endpoint
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


# Technology signatures for header matching
HEADER_SIGNATURES: Dict[str, List[Tuple[str, str]]] = {
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
        (r"Jetty/?(\d+\.?\d*)?", "Jetty"),
        (r"Tomcat/?(\d+\.?\d*)?", "Apache Tomcat"),
        (r"WEBrick/?(\d+\.\d+\.?\d*)?", "WEBrick"),
        (r"Tengine/?(\d+\.\d+\.?\d*)?", "Tengine"),
        (r"deno", "Deno"),
    ],
    # X-Powered-By header patterns
    "X-Powered-By": [
        (r"PHP/?(\d+\.\d+\.?\d*)?", "PHP"),
        (r"ASP\.NET", "ASP.NET"),
        (r"Express", "Express.js"),
        (r"Next\.js/?(\d+\.?\d*)?", "Next.js"),
        (r"Nuxt\.?j?s?/?(\d+\.?\d*)?", "Nuxt.js"),
        (r"Phusion Passenger", "Phusion Passenger"),
        (r"PleskLin", "Plesk"),
        (r"JSF/?(\d+\.?\d*)?", "JavaServer Faces"),
        (r"Servlet/?(\d+\.?\d*)?", "Java Servlet"),
        (r"Ruby", "Ruby"),
        (r"Python/?(\d+\.?\d*)?", "Python"),
        (r"Flask", "Flask"),
        (r"Django/?(\d+\.?\d*)?", "Django"),
        (r"Laravel", "Laravel"),
        (r"Symfony", "Symfony"),
        (r"CakePHP", "CakePHP"),
        (r"CodeIgniter", "CodeIgniter"),
        (r"Craft CMS", "Craft CMS"),
        (r"Phalcon", "Phalcon"),
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
        (r"Drupal\s*(\d+)?", "Drupal"),
        (r"WordPress\s*(\d+\.?\d*)?", "WordPress"),
        (r"Joomla", "Joomla"),
        (r"STARTER STARTER", "Starter Theme"),
        (r"Hugo\s*(\d+\.?\d*)?", "Hugo"),
        (r"Jekyll", "Jekyll"),
        (r"Gatsby", "Gatsby"),
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

# Wappalyzer-style HTML/JS patterns for technology detection
HTML_PATTERNS: List[Tuple[str, str, Optional[str]]] = [
    # CMS Detection
    (r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s*([\d.]*)', "WordPress", "CMS"),
    (r'wp-content/themes/', "WordPress", "CMS"),
    (r'wp-includes/', "WordPress", "CMS"),
    (r'/wp-json/', "WordPress", "CMS"),
    (r'<meta\s+name=["\']generator["\']\s+content=["\']Drupal\s*([\d.]*)', "Drupal", "CMS"),
    (r'Drupal\.settings', "Drupal", "CMS"),
    (r'/sites/default/files/', "Drupal", "CMS"),
    (r'<meta\s+name=["\']generator["\']\s+content=["\']Joomla', "Joomla", "CMS"),
    (r'/media/jui/', "Joomla", "CMS"),
    (r'<meta\s+name=["\']generator["\']\s+content=["\']TYPO3', "TYPO3", "CMS"),
    (r'<meta\s+name=["\']generator["\']\s+content=["\']Shopify', "Shopify", "E-commerce"),
    (r'cdn\.shopify\.com', "Shopify", "E-commerce"),
    (r'<meta\s+name=["\']generator["\']\s+content=["\']Wix\.com', "Wix", "CMS"),
    (r'static\.wixstatic\.com', "Wix", "CMS"),
    (r'<meta\s+name=["\']generator["\']\s+content=["\']Squarespace', "Squarespace", "CMS"),
    (r'squarespace\.com', "Squarespace", "CMS"),
    (r'<meta\s+name=["\']generator["\']\s+content=["\']Ghost\s*([\d.]*)', "Ghost", "CMS"),
    (r'<meta\s+name=["\']generator["\']\s+content=["\']Hugo\s*([\d.]*)', "Hugo", "Static Site"),
    (r'<meta\s+name=["\']generator["\']\s+content=["\']Jekyll', "Jekyll", "Static Site"),
    (r'<meta\s+name=["\']generator["\']\s+content=["\']Gatsby', "Gatsby", "Static Site"),
    (r'<meta\s+name=["\']generator["\']\s+content=["\']Hexo', "Hexo", "Static Site"),
    
    # JavaScript Frameworks
    (r'React', "React", "JavaScript Framework"),
    (r'__NEXT_DATA__', "Next.js", "JavaScript Framework"),
    (r'/_next/static/', "Next.js", "JavaScript Framework"),
    (r'__NUXT__', "Nuxt.js", "JavaScript Framework"),
    (r'/_nuxt/', "Nuxt.js", "JavaScript Framework"),
    (r'ng-version=', "Angular", "JavaScript Framework"),
    (r'ng-app', "AngularJS", "JavaScript Framework"),
    (r'Vue\.js', "Vue.js", "JavaScript Framework"),
    (r'vue\.min\.js', "Vue.js", "JavaScript Framework"),
    (r'vue\.runtime', "Vue.js", "JavaScript Framework"),
    (r'data-v-[a-f0-9]', "Vue.js", "JavaScript Framework"),
    (r'svelte', "Svelte", "JavaScript Framework"),
    (r'ember', "Ember.js", "JavaScript Framework"),
    (r'backbone', "Backbone.js", "JavaScript Framework"),
    
    # JavaScript Libraries
    (r'jquery[.-]?([\d.]*)?\.(?:min\.)?js', "jQuery", "JavaScript Library"),
    (r'jQuery\s+v?([\d.]+)', "jQuery", "JavaScript Library"),
    (r'bootstrap[.-]?([\d.]*)?\.(?:min\.)?(?:js|css)', "Bootstrap", "CSS Framework"),
    (r'tailwindcss', "Tailwind CSS", "CSS Framework"),
    (r'bulma', "Bulma", "CSS Framework"),
    (r'foundation', "Foundation", "CSS Framework"),
    (r'materialize', "Materialize", "CSS Framework"),
    (r'lodash', "Lodash", "JavaScript Library"),
    (r'underscore', "Underscore.js", "JavaScript Library"),
    (r'moment\.js', "Moment.js", "JavaScript Library"),
    (r'axios', "Axios", "JavaScript Library"),
    (r'socket\.io', "Socket.io", "JavaScript Library"),
    
    # Analytics & Marketing
    (r'google-analytics\.com/(?:ga|analytics)\.js', "Google Analytics", "Analytics"),
    (r'gtag\(|gtm\.js', "Google Tag Manager", "Analytics"),
    (r'googletagmanager\.com', "Google Tag Manager", "Analytics"),
    (r'facebook\.net/.*fbevents\.js', "Facebook Pixel", "Analytics"),
    (r'hotjar\.com', "Hotjar", "Analytics"),
    (r'segment\.com|segment\.io', "Segment", "Analytics"),
    (r'mixpanel\.com', "Mixpanel", "Analytics"),
    (r'amplitude\.com', "Amplitude", "Analytics"),
    (r'plausible\.io', "Plausible", "Analytics"),
    
    # E-commerce
    (r'WooCommerce', "WooCommerce", "E-commerce"),
    (r'Magento', "Magento", "E-commerce"),
    (r'/skin/frontend/', "Magento", "E-commerce"),
    (r'PrestaShop', "PrestaShop", "E-commerce"),
    (r'BigCommerce', "BigCommerce", "E-commerce"),
    (r'OpenCart', "OpenCart", "E-commerce"),
    
    # Security
    (r'cloudflare', "Cloudflare", "CDN/Security"),
    (r'akamai', "Akamai", "CDN/Security"),
    (r'sucuri', "Sucuri", "Security"),
    (r'wordfence', "Wordfence", "Security"),
    (r'recaptcha', "reCAPTCHA", "Security"),
    (r'hcaptcha', "hCaptcha", "Security"),
    
    # Hosting/Infrastructure
    (r'netlify', "Netlify", "Hosting"),
    (r'vercel', "Vercel", "Hosting"),
    (r'heroku', "Heroku", "Hosting"),
    (r'aws\.amazon', "AWS", "Cloud"),
    (r'azure', "Azure", "Cloud"),
    (r'digitalocean', "DigitalOcean", "Cloud"),
]

# WAF Detection patterns
WAF_SIGNATURES: List[Tuple[str, str]] = [
    (r"cloudflare", "Cloudflare WAF"),
    (r"akamai", "Akamai WAF"),
    (r"sucuri", "Sucuri WAF"),
    (r"imperva|incapsula", "Imperva/Incapsula"),
    (r"f5|big-?ip", "F5 BIG-IP"),
    (r"barracuda", "Barracuda WAF"),
    (r"fortinet|fortigate", "Fortinet FortiWeb"),
    (r"aws.*waf|awselb", "AWS WAF"),
    (r"mod_security|modsecurity", "ModSecurity"),
    (r"wordfence", "Wordfence"),
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
        - HTML/JS content analysis (Wappalyzer-style)
        - WAF detection
        - Version extraction
        - Real NVD CVE lookup with fallback to mock database
    """

    def __init__(
        self,
        timeout: float = 10.0,
        max_concurrent: int = 20,
        follow_redirects: bool = True,
        verify_ssl: bool = False,
        nvd_api_key: Optional[str] = None,
        use_nvd: bool = True,
    ) -> None:
        """
        Initialize the tech fingerprinter.

        Args:
            timeout: HTTP request timeout in seconds
            max_concurrent: Maximum concurrent HTTP requests
            follow_redirects: Whether to follow HTTP redirects
            verify_ssl: Whether to verify SSL certificates
            nvd_api_key: Optional NVD API key for increased rate limits
            use_nvd: Whether to use real NVD API (falls back to mock if fails)
        """
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.follow_redirects = follow_redirects
        self.verify_ssl = verify_ssl
        self.nvd_api_key = nvd_api_key
        self.use_nvd = use_nvd
        self.logger = get_logger()
        
        # Cache for NVD results to avoid duplicate lookups
        self._nvd_cache: Dict[str, List[Dict]] = {}

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

    async def fetch_page_content(self, url: str) -> Optional[str]:
        """
        Fetch full page HTML content for analysis.

        Args:
            url: The URL to fetch

        Returns:
            HTML content string or None on error
        """
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=self.follow_redirects,
                verify=self.verify_ssl,
            ) as client:
                response = await client.get(url)
                content_type = response.headers.get("content-type", "")
                
                # Only process HTML content
                if "text/html" not in content_type.lower():
                    self.logger.debug(f"Skipping non-HTML content from {url}")
                    return None
                
                self.logger.debug(f"Fetched {len(response.text)} bytes from {url}")
                return response.text

        except Exception as e:
            self.logger.debug(f"Error fetching page content from {url}: {e}")
            return None

    def analyze_html_content(self, html: str) -> List[TechFingerprint]:
        """
        Analyze HTML content for technology signatures.

        Uses Wappalyzer-style pattern matching to detect:
        - CMS (WordPress, Drupal, Joomla, etc.)
        - JavaScript frameworks (React, Vue, Angular, etc.)
        - JS libraries (jQuery, Bootstrap, etc.)
        - Analytics tools (Google Analytics, etc.)
        - E-commerce platforms
        - Security tools and WAFs

        Args:
            html: HTML page content

        Returns:
            List of detected TechFingerprint objects
        """
        detected: Dict[str, TechFingerprint] = {}

        for pattern, tech_name, category in HTML_PATTERNS:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                version = None
                # Try to extract version from capture groups
                if match.groups():
                    for group in match.groups():
                        if group and re.match(r"[\d.]+", group):
                            version = group
                            break

                key = f"{tech_name}_{version or 'unknown'}"
                if key not in detected:
                    detected[key] = TechFingerprint(
                        name=tech_name,
                        version=version,
                        source=f"html ({category})" if category else "html",
                        confidence="medium",
                    )
                    self.logger.debug(
                        f"Detected {tech_name}"
                        + (f" {version}" if version else "")
                        + f" from HTML ({category})"
                    )

        return list(detected.values())

    def detect_waf(self, headers: httpx.Headers, html: Optional[str] = None) -> Optional[str]:
        """
        Detect Web Application Firewall from response.

        Args:
            headers: HTTP response headers
            html: Optional HTML content

        Returns:
            WAF name if detected, None otherwise
        """
        # Check headers
        all_headers = " ".join(f"{k}: {v}" for k, v in headers.items())
        
        for pattern, waf_name in WAF_SIGNATURES:
            if re.search(pattern, all_headers, re.IGNORECASE):
                self.logger.info(f"WAF detected: {waf_name}")
                return waf_name
        
        # Check HTML for WAF indicators
        if html:
            for pattern, waf_name in WAF_SIGNATURES:
                if re.search(pattern, html, re.IGNORECASE):
                    self.logger.info(f"WAF detected from HTML: {waf_name}")
                    return waf_name
        
        return None

    async def search_nvd_cves(
        self,
        tech_name: str,
        version: Optional[str] = None,
        max_results: int = 5,
    ) -> List[Dict]:
        """
        Search NVD for real CVEs matching a technology.

        Args:
            tech_name: Name of the technology (e.g., "Apache", "PHP")
            version: Optional version string
            max_results: Maximum CVEs to return per technology

        Returns:
            List of CVE dictionaries with id, severity, score, description
        """
        cache_key = f"{tech_name}_{version or 'any'}"
        
        # Check cache first
        if cache_key in self._nvd_cache:
            return self._nvd_cache[cache_key]

        if not self.use_nvd:
            return []

        cves = []
        
        try:
            # Build search keyword
            keyword = tech_name
            if version:
                keyword = f"{tech_name} {version}"
            
            params = {
                "keywordSearch": keyword,
                "resultsPerPage": min(max_results * 2, 20),  # Fetch extra to filter
            }
            
            headers = {"Accept": "application/json"}
            if self.nvd_api_key:
                headers["apiKey"] = self.nvd_api_key
            
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    NVD_API_URL,
                    params=params,
                    headers=headers,
                )
                
                if response.status_code == 200:
                    data = response.json()
                    vulnerabilities = data.get("vulnerabilities", [])
                    
                    for vuln in vulnerabilities[:max_results]:
                        cve_data = vuln.get("cve", {})
                        cve_id = cve_data.get("id", "Unknown")
                        
                        # Extract CVSS score and severity
                        metrics = cve_data.get("metrics", {})
                        cvss_score = None
                        severity = "Unknown"
                        
                        # Try CVSS 3.1 first, then 3.0, then 2.0
                        for cvss_version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                            if cvss_version in metrics and metrics[cvss_version]:
                                cvss_data = metrics[cvss_version][0].get("cvssData", {})
                                cvss_score = cvss_data.get("baseScore")
                                severity = cvss_data.get("baseSeverity", "Unknown")
                                break
                        
                        # Get description
                        descriptions = cve_data.get("descriptions", [])
                        description = "No description available"
                        for desc in descriptions:
                            if desc.get("lang") == "en":
                                description = desc.get("value", description)
                                break
                        
                        cves.append({
                            "cve_id": cve_id,
                            "severity": severity,
                            "cvss_score": cvss_score,
                            "description": description[:300] + "..." if len(description) > 300 else description,
                            "source": "NVD",
                        })
                        
                        self.logger.debug(f"Found CVE: {cve_id} ({severity})")
                
                elif response.status_code == 403:
                    self.logger.warning("NVD API rate limited. Consider using --nvd-key")
                else:
                    self.logger.debug(f"NVD API returned status {response.status_code}")
                    
        except httpx.TimeoutException:
            self.logger.debug("NVD API request timed out")
        except Exception as e:
            self.logger.debug(f"NVD API error: {e}")
        
        # Cache results (even empty ones to avoid repeated failures)
        self._nvd_cache[cache_key] = cves
        return cves

    async def get_cves_for_tech(
        self,
        tech_name: str,
        version: Optional[str] = None,
    ) -> List[Dict]:
        """
        Get CVEs for a technology, using NVD with mock fallback.

        Args:
            tech_name: Technology name
            version: Optional version string

        Returns:
            List of CVE dictionaries
        """
        cves = []
        
        # Try real NVD lookup first
        if self.use_nvd:
            cves = await self.search_nvd_cves(tech_name, version)
        
        # Fall back to mock database if no NVD results
        if not cves:
            mock_cve = self.get_mock_cve(tech_name, version)
            if mock_cve:
                mock_cve["source"] = "mock_database"
                cves = [mock_cve]
        
        return cves

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
        analyze_content: bool = True,
    ) -> Tuple[List[TechFingerprint], Optional[str], Optional[Dict[str, Any]]]:
        """
        Fingerprint technologies on a host.

        Args:
            hostname: Hostname to fingerprint
            ports: Optional list of ports to check (default: [80, 443])
            analyze_content: Whether to fetch and analyze page content

        Returns:
            Tuple of (List of detected TechFingerprint objects, detected WAF name or None, HTTP response info)
        """
        ports = ports or [443, 80]
        all_fingerprints: Dict[str, TechFingerprint] = {}
        detected_waf: Optional[str] = None
        http_response_info: Optional[Dict[str, Any]] = None

        for port in ports:
            scheme = "https" if port == 443 else "http"
            url = f"{scheme}://{hostname}:{port}" if port not in (80, 443) else f"{scheme}://{hostname}"

            # Fetch headers
            headers, cookies = await self.analyze_headers(url)
            if headers is None:
                continue
            
            # Store HTTP response info from first successful connection
            if http_response_info is None:
                http_response_info = {
                    "url": url,
                    "status_code": headers.get(":status", "200"),  # httpx doesn't expose status directly here
                    "server": headers.get("server"),
                    "content_type": headers.get("content-type"),
                    "x_powered_by": headers.get("x-powered-by"),
                    "headers": dict(headers),
                }

            # Match technologies from headers
            fingerprints = self.match_tech(headers, cookies)
            
            # Fetch and analyze HTML content
            html_content = None
            if analyze_content:
                html_content = await self.fetch_page_content(url)
                if html_content:
                    html_fingerprints = self.analyze_html_content(html_content)
                    fingerprints.extend(html_fingerprints)
            
            # Detect WAF
            if not detected_waf:
                detected_waf = self.detect_waf(headers, html_content)
            
            # Add CVE data and deduplicate
            for fp in fingerprints:
                # Get CVEs (real NVD or mock fallback)
                cves = await self.get_cves_for_tech(fp.name, fp.version)
                if cves:
                    fp.cves.extend(cves)
                    for cve in cves:
                        source = cve.get("source", "unknown")
                        self.logger.warning(
                            f"Potential vulnerability: {fp.name} "
                            f"-> {cve['cve_id']} ({cve['severity']}) [{source}]"
                        )
                
                key = f"{fp.name}_{fp.version or 'unknown'}"
                if key not in all_fingerprints:
                    all_fingerprints[key] = fp
                else:
                    # Merge CVEs if duplicate
                    existing_cve_ids = {c["cve_id"] for c in all_fingerprints[key].cves}
                    for cve in fp.cves:
                        if cve["cve_id"] not in existing_cve_ids:
                            all_fingerprints[key].cves.append(cve)

        return list(all_fingerprints.values()), detected_waf, http_response_info

    async def run(
        self,
        hostnames: List[str],
        analyze_content: bool = True,
    ) -> Dict[str, Any]:
        """
        Run fingerprinting on multiple hosts.

        Args:
            hostnames: List of hostnames to fingerprint
            analyze_content: Whether to fetch and analyze page content

        Returns:
            Dictionary with 'technologies' mapping hostname to TechFingerprints,
            'wafs' mapping hostname to detected WAF, and 'responses' with HTTP info
        """
        self.logger.info(f"Starting technology fingerprinting on {len(hostnames)} hosts")
        
        results: Dict[str, List[TechFingerprint]] = {}
        wafs: Dict[str, str] = {}
        responses: Dict[str, Dict[str, Any]] = {}
        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def fingerprint_with_limit(host: str) -> Tuple[str, List[TechFingerprint], Optional[str], Optional[Dict[str, Any]]]:
            async with semaphore:
                fingerprints, waf, response_info = await self.fingerprint_host(host, analyze_content=analyze_content)
                return host, fingerprints, waf, response_info

        tasks = [fingerprint_with_limit(host) for host in hostnames]
        completed = await asyncio.gather(*tasks, return_exceptions=True)

        for result in completed:
            if isinstance(result, Exception):
                self.logger.debug(f"Fingerprinting error: {result}")
                continue
            hostname, fingerprints, waf, response_info = result
            if fingerprints:
                results[hostname] = fingerprints
                self.logger.info(
                    f"{hostname}: {len(fingerprints)} technologies detected"
                )
            if waf:
                wafs[hostname] = waf
            if response_info:
                responses[hostname] = response_info

        # Summary
        total_techs = sum(len(fps) for fps in results.values())
        total_cves = sum(
            len(fp.cves) for fps in results.values() for fp in fps
        )
        
        self.logger.info(
            f"Fingerprinting complete: {total_techs} technologies, "
            f"{total_cves} potential vulnerabilities, {len(wafs)} WAFs detected"
        )

        return {
            "technologies": results,
            "wafs": wafs,
            "responses": responses,
        }
