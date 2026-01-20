"""
OSINT Collection Module for RedSurface.
Collects email addresses and employee data from multiple public sources.
"""

import asyncio
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
import httpx

try:
    import dns.asyncresolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

from utils.logger import get_logger


@dataclass
class PersonInfo:
    """Represents a discovered person/employee."""
    
    email: Optional[str] = None
    name: str = "Unknown"
    role: str = "Unknown"
    source: str = "Unknown"
    
    def to_dict(self) -> dict:
        """Convert to dictionary representation."""
        return {
            "email": self.email,
            "name": self.name,
            "role": self.role,
            "source": self.source,
        }


@dataclass
class OSINTResults:
    """Aggregated OSINT collection results."""
    
    emails: Set[str] = field(default_factory=set)
    people: List[PersonInfo] = field(default_factory=list)
    sources_queried: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    dns_hints: Dict[str, Any] = field(default_factory=dict)
    email_pattern: Optional[str] = None
    verified_emails: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        """Convert to dictionary representation."""
        return {
            "emails": sorted(list(self.emails)),
            "people": [p.to_dict() for p in self.people],
            "sources_queried": self.sources_queried,
            "errors": self.errors,
            "dns_hints": self.dns_hints,
            "email_pattern": self.email_pattern,
            "verified_emails": self.verified_emails,
            "total_emails": len(self.emails),
            "total_people": len(self.people),
        }


class OSINTCollector:
    """
    Collects OSINT data (emails, employee info) from multiple public sources.
    
    Sources:
        - PGP Key Servers (technical staff)
        - GitHub Public API (developers)
        - Hunter.io API (business contacts, requires API key)
        - Phonebook.cz (free email search)
        - Skymem (corporate email scraping)
        - WHOIS/RDAP (domain contacts)
        - Have I Been Pwned (breached emails, requires API key)
        - DNS Records (MX, SPF, DMARC analysis)
    """

    # PGP Key Server endpoints
    PGP_SERVERS = [
        "https://keyserver.ubuntu.com/pks/lookup",
        "https://keys.openpgp.org/search",
    ]

    # GitHub API endpoint
    GITHUB_API = "https://api.github.com"

    # Hunter.io API endpoint
    HUNTER_API = "https://api.hunter.io/v2"

    # RDAP endpoint for WHOIS lookups
    RDAP_SERVERS = [
        "https://rdap.verisign.com/com/v1/domain/",
        "https://rdap.org/domain/",
    ]

    # Common email patterns for permutation generation
    EMAIL_PATTERNS = [
        "{first}.{last}",           # john.doe
        "{first}{last}",            # johndoe
        "{first}_{last}",           # john_doe
        "{f}{last}",                # jdoe
        "{first}{l}",               # johnd
        "{first}",                  # john
        "{last}.{first}",           # doe.john
        "{last}{first}",            # doejohn
        "{f}.{last}",               # j.doe
        "{first}.{l}",              # john.d
        "{last}",                   # doe
        "{f}{l}",                   # jd
    ]

    def __init__(
        self,
        timeout: float = 15.0,
        max_retries: int = 2,
        github_token: Optional[str] = None,
        use_system_dns: bool = True,
    ) -> None:
        """
        Initialize the OSINT collector.

        Args:
            timeout: HTTP request timeout in seconds
            max_retries: Maximum retry attempts for failed requests
            github_token: Optional GitHub personal access token for higher rate limits
            use_system_dns: Use system DNS instead of public DNS servers
        """
        self.timeout = timeout
        self.max_retries = max_retries
        self.github_token = github_token
        self.use_system_dns = use_system_dns
        self.logger = get_logger()

    def _build_email_pattern(self, domain: str) -> re.Pattern:
        """
        Build a regex pattern to match emails for a specific domain.

        Args:
            domain: Target domain

        Returns:
            Compiled regex pattern
        """
        # Escape dots in domain for regex
        escaped_domain = re.escape(domain)
        # Match email addresses for this domain
        pattern = rf'[a-zA-Z0-9._%+-]+@(?:[a-zA-Z0-9-]+\.)*{escaped_domain}'
        return re.compile(pattern, re.IGNORECASE)

    async def search_pgp(self, domain: str) -> List[PersonInfo]:
        """
        Search PGP key servers for email addresses.
        
        PGP key servers contain public keys uploaded by technical users,
        making this an excellent source for finding developer/sysadmin emails.

        Args:
            domain: Target domain to search

        Returns:
            List of PersonInfo objects found
        """
        self.logger.debug(f"Searching PGP key servers for {domain}")
        results: List[PersonInfo] = []
        found_emails: Set[str] = set()
        email_pattern = self._build_email_pattern(domain)

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            # Search Ubuntu Key Server
            try:
                url = f"{self.PGP_SERVERS[0]}?search={domain}&op=index"
                response = await client.get(url)
                
                if response.status_code == 200:
                    # Parse HTML response for email addresses
                    text = response.text
                    matches = email_pattern.findall(text)
                    
                    for email in matches:
                        email_lower = email.lower()
                        if email_lower not in found_emails:
                            found_emails.add(email_lower)
                            # Try to extract name from PGP key data
                            name = self._extract_pgp_name(text, email)
                            results.append(PersonInfo(
                                email=email_lower,
                                name=name,
                                role="PGP Key Owner",
                                source="PGP Key Server (Ubuntu)",
                            ))
                    
                    self.logger.debug(
                        f"PGP Ubuntu: Found {len(matches)} email(s) for {domain}"
                    )
                else:
                    self.logger.debug(
                        f"PGP Ubuntu returned status {response.status_code}"
                    )

            except httpx.TimeoutException:
                self.logger.debug(f"PGP Ubuntu key server timeout for {domain}")
            except Exception as e:
                self.logger.debug(f"PGP Ubuntu search error: {e}")

            # Search OpenPGP.org
            try:
                url = f"{self.PGP_SERVERS[1]}?q={domain}"
                response = await client.get(url)
                
                if response.status_code == 200:
                    text = response.text
                    matches = email_pattern.findall(text)
                    
                    for email in matches:
                        email_lower = email.lower()
                        if email_lower not in found_emails:
                            found_emails.add(email_lower)
                            results.append(PersonInfo(
                                email=email_lower,
                                name="Unknown",
                                role="PGP Key Owner",
                                source="PGP Key Server (OpenPGP)",
                            ))
                    
                    self.logger.debug(
                        f"PGP OpenPGP: Found {len(matches)} email(s) for {domain}"
                    )

            except httpx.TimeoutException:
                self.logger.debug(f"OpenPGP key server timeout for {domain}")
            except Exception as e:
                self.logger.debug(f"OpenPGP search error: {e}")

        if results:
            self.logger.info(f"PGP servers: Found {len(results)} unique email(s)")
        
        return results

    def _extract_pgp_name(self, html_text: str, email: str) -> str:
        """
        Try to extract a name associated with an email from PGP key HTML.

        Args:
            html_text: Raw HTML from PGP server
            email: Email to find name for

        Returns:
            Extracted name or "Unknown"
        """
        # PGP key listings often have format: "Name <email>"
        pattern = rf'([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)+)\s*&lt;{re.escape(email)}&gt;'
        match = re.search(pattern, html_text, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        
        # Try alternate format without HTML encoding
        pattern = rf'([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)+)\s*<{re.escape(email)}>'
        match = re.search(pattern, html_text, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        
        return "Unknown"

    async def search_github(self, domain: str) -> List[PersonInfo]:
        """
        Search GitHub for users with emails matching the target domain.
        
        GitHub's public API can reveal developers who have their email public
        or who have committed code with emails visible in their profile.

        Args:
            domain: Target domain to search

        Returns:
            List of PersonInfo objects found
        """
        self.logger.debug(f"Searching GitHub for users with {domain} emails")
        results: List[PersonInfo] = []
        found_emails: Set[str] = set()

        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "RedSurface-OSINT/1.0",
        }
        
        # Add auth token if available (increases rate limit)
        if self.github_token:
            headers["Authorization"] = f"token {self.github_token}"

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                # Search for users with domain in their email
                search_url = f"{self.GITHUB_API}/search/users"
                params = {
                    "q": f"{domain} in:email",
                    "type": "Users",
                    "per_page": 30,
                }
                
                response = await client.get(search_url, headers=headers, params=params)
                
                if response.status_code == 200:
                    data = response.json()
                    users = data.get("items", [])
                    
                    # For each user, try to get their public email
                    for user in users[:20]:  # Limit to avoid rate limits
                        login = user.get("login", "")
                        
                        # Get user details
                        try:
                            user_url = f"{self.GITHUB_API}/users/{login}"
                            user_response = await client.get(user_url, headers=headers)
                            
                            if user_response.status_code == 200:
                                user_data = user_response.json()
                                email = user_data.get("email")
                                name = user_data.get("name") or login
                                company = user_data.get("company", "")
                                bio = user_data.get("bio", "")
                                
                                if email and domain.lower() in email.lower():
                                    email_lower = email.lower()
                                    if email_lower not in found_emails:
                                        found_emails.add(email_lower)
                                        
                                        # Determine role from bio/company
                                        role = "Developer"
                                        if company:
                                            role = f"Developer at {company}"
                                        
                                        results.append(PersonInfo(
                                            email=email_lower,
                                            name=name,
                                            role=role,
                                            source="GitHub",
                                        ))
                            
                            # Small delay to respect rate limits
                            await asyncio.sleep(0.5)
                            
                        except Exception as e:
                            self.logger.debug(f"GitHub user fetch error for {login}: {e}")
                            continue
                    
                    self.logger.debug(
                        f"GitHub: Found {len(results)} user(s) with {domain} emails"
                    )

                elif response.status_code == 403:
                    # Rate limit exceeded
                    rate_limit = response.headers.get("X-RateLimit-Remaining", "?")
                    self.logger.warning(
                        f"GitHub API rate limit exceeded (remaining: {rate_limit}). "
                        "Consider providing a GitHub token for higher limits."
                    )
                    
                elif response.status_code == 401:
                    self.logger.warning("GitHub API authentication failed")
                    
                else:
                    self.logger.debug(
                        f"GitHub search returned status {response.status_code}"
                    )

            except httpx.TimeoutException:
                self.logger.debug(f"GitHub API timeout for {domain}")
            except Exception as e:
                self.logger.debug(f"GitHub search error: {e}")

        if results:
            self.logger.info(f"GitHub: Found {len(results)} email(s)")
        
        return results

    async def search_hunter(
        self,
        domain: str,
        api_key: Optional[str] = None,
    ) -> List[PersonInfo]:
        """
        Search Hunter.io for business email addresses.
        
        Hunter.io is a professional email finder service that provides
        verified business emails along with employee names and positions.

        Args:
            domain: Target domain to search
            api_key: Hunter.io API key (required)

        Returns:
            List of PersonInfo objects found
        """
        if not api_key:
            self.logger.debug("Hunter.io: No API key provided, skipping")
            return []

        self.logger.debug(f"Searching Hunter.io for {domain}")
        results: List[PersonInfo] = []

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                url = f"{self.HUNTER_API}/domain-search"
                params = {
                    "domain": domain,
                    "api_key": api_key,
                }
                
                response = await client.get(url, params=params)
                
                if response.status_code == 200:
                    data = response.json()
                    emails_data = data.get("data", {}).get("emails", [])
                    
                    for entry in emails_data:
                        email = entry.get("value", "").lower()
                        first_name = entry.get("first_name", "")
                        last_name = entry.get("last_name", "")
                        position = entry.get("position", "Unknown")
                        confidence = entry.get("confidence", 0)
                        
                        if email:
                            # Build full name
                            name_parts = [n for n in [first_name, last_name] if n]
                            name = " ".join(name_parts) if name_parts else "Unknown"
                            
                            results.append(PersonInfo(
                                email=email,
                                name=name,
                                role=position or "Unknown",
                                source=f"Hunter.io (confidence: {confidence}%)",
                            ))
                    
                    # Also get pattern and organization info
                    pattern = data.get("data", {}).get("pattern")
                    org = data.get("data", {}).get("organization")
                    
                    if pattern:
                        self.logger.debug(f"Hunter.io: Email pattern for {domain}: {pattern}")
                    if org:
                        self.logger.debug(f"Hunter.io: Organization: {org}")
                    
                    self.logger.info(f"Hunter.io: Found {len(results)} email(s)")

                elif response.status_code == 401:
                    self.logger.warning("Hunter.io: Invalid API key")
                    
                elif response.status_code == 429:
                    self.logger.warning("Hunter.io: Rate limit exceeded")
                    
                else:
                    error_msg = response.json().get("errors", [{}])[0].get("details", "Unknown error")
                    self.logger.debug(f"Hunter.io error: {error_msg}")

            except httpx.TimeoutException:
                self.logger.debug(f"Hunter.io timeout for {domain}")
            except Exception as e:
                self.logger.debug(f"Hunter.io search error: {e}")

        return results

    async def search_crtsh(self, domain: str) -> List[str]:
        """
        Search crt.sh for emails in SSL certificate transparency logs.
        
        Certificate transparency logs sometimes contain email addresses
        in the certificate subject or SAN fields.

        Args:
            domain: Target domain to search

        Returns:
            List of email addresses found
        """
        self.logger.debug(f"Searching crt.sh for {domain}")
        emails: Set[str] = set()
        email_pattern = self._build_email_pattern(domain)

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                url = f"https://crt.sh/?q=%.{domain}&output=json"
                response = await client.get(url)
                
                if response.status_code == 200:
                    certs = response.json()
                    
                    for cert in certs:
                        # Check name_value field for emails
                        name_value = cert.get("name_value", "")
                        matches = email_pattern.findall(name_value)
                        emails.update(e.lower() for e in matches)
                    
                    if emails:
                        self.logger.debug(f"crt.sh: Found {len(emails)} email(s)")

            except Exception as e:
                self.logger.debug(f"crt.sh search error: {e}")

        return list(emails)
#test
    async def search_phonebook(self, domain: str) -> List[str]:
        """
        Search Phonebook.cz for emails (free, no API key needed).
        One of the best free sources for corporate emails.

        Args:
            domain: Target domain to search

        Returns:
            List of email addresses found
        """
        self.logger.debug(f"Searching Phonebook.cz for {domain}")
        emails: Set[str] = set()
        email_pattern = self._build_email_pattern(domain)

        # Phonebook.cz uses a different approach - search their cached data
        urls = [
            f"https://phonebook.cz/api/v1/search?q=@{domain}&type=email",
            f"https://phonebook.cz/search?q=@{domain}",
        ]

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for url in urls:
                try:
                    response = await client.get(url, follow_redirects=True)
                    
                    if response.status_code == 200:
                        # Try JSON parsing first
                        try:
                            data = response.json()
                            if isinstance(data, dict):
                                results = data.get("results", data.get("emails", []))
                                for item in results:
                                    if isinstance(item, str) and domain.lower() in item.lower():
                                        emails.add(item.lower())
                                    elif isinstance(item, dict):
                                        email = item.get("email", item.get("value", ""))
                                        if email and domain.lower() in email.lower():
                                            emails.add(email.lower())
                        except:
                            # Fall back to regex extraction from HTML
                            matches = email_pattern.findall(response.text)
                            emails.update(e.lower() for e in matches)
                        
                        if emails:
                            break

                except httpx.TimeoutException:
                    self.logger.debug(f"Phonebook.cz timeout for {domain}")
                except Exception as e:
                    self.logger.debug(f"Phonebook.cz search error: {e}")

        if emails:
            self.logger.info(f"Phonebook.cz: Found {len(emails)} email(s)")
        
        return list(emails)

    async def search_skymem(self, domain: str) -> List[str]:
        """
        Scrape Skymem.info for corporate emails.
        
        Skymem aggregates emails from various public sources
        and provides a searchable database.

        Args:
            domain: Target domain to search

        Returns:
            List of email addresses found
        """
        self.logger.debug(f"Searching Skymem for {domain}")
        emails: Set[str] = set()
        email_pattern = self._build_email_pattern(domain)

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                # Skymem search URL
                url = f"https://www.skymem.info/srch?q={domain}&ss=home"
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Accept": "text/html,application/xhtml+xml",
                }
                
                response = await client.get(url, headers=headers, follow_redirects=True)
                
                if response.status_code == 200:
                    # Extract emails from HTML response
                    matches = email_pattern.findall(response.text)
                    emails.update(e.lower() for e in matches)
                    
                    # Also check for domain-specific page
                    if emails:
                        self.logger.debug(f"Skymem: Found {len(emails)} email(s)")

            except httpx.TimeoutException:
                self.logger.debug(f"Skymem timeout for {domain}")
            except Exception as e:
                self.logger.debug(f"Skymem search error: {e}")

        if emails:
            self.logger.info(f"Skymem: Found {len(emails)} email(s)")
        
        return list(emails)

    async def search_whois_contacts(self, domain: str) -> List[PersonInfo]:
        """
        Extract contact emails from WHOIS/RDAP records.
        
        RDAP (Registration Data Access Protocol) provides structured
        domain registration data including admin/tech contacts.

        Args:
            domain: Target domain to search

        Returns:
            List of PersonInfo objects with contact details
        """
        self.logger.debug(f"Searching WHOIS/RDAP for {domain}")
        results: List[PersonInfo] = []
        found_emails: Set[str] = set()

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for rdap_base in self.RDAP_SERVERS:
                try:
                    url = f"{rdap_base}{domain}"
                    response = await client.get(url, follow_redirects=True)
                    
                    if response.status_code == 200:
                        data = response.json()
                        
                        # Extract emails from entities (registrant, admin, tech contacts)
                        for entity in data.get("entities", []):
                            roles = entity.get("roles", [])
                            role_str = ", ".join(roles) if roles else "Contact"
                            
                            # Parse vCard data
                            vcard = entity.get("vcardArray", [])
                            if len(vcard) > 1:
                                name = "Unknown"
                                email = None
                                
                                for item in vcard[1]:
                                    if isinstance(item, list) and len(item) >= 4:
                                        if item[0] == "fn":
                                            name = item[3]
                                        elif item[0] == "email":
                                            email = item[3].lower()
                                
                                if email and email not in found_emails:
                                    found_emails.add(email)
                                    results.append(PersonInfo(
                                        email=email,
                                        name=name,
                                        role=f"WHOIS {role_str.title()}",
                                        source="WHOIS/RDAP",
                                    ))
                            
                            # Check nested entities
                            for nested in entity.get("entities", []):
                                nested_vcard = nested.get("vcardArray", [])
                                if len(nested_vcard) > 1:
                                    for item in nested_vcard[1]:
                                        if isinstance(item, list) and item[0] == "email":
                                            email = item[3].lower()
                                            if email not in found_emails:
                                                found_emails.add(email)
                                                results.append(PersonInfo(
                                                    email=email,
                                                    name="Unknown",
                                                    role=f"WHOIS {role_str.title()}",
                                                    source="WHOIS/RDAP",
                                                ))
                        
                        if results:
                            break

                except httpx.TimeoutException:
                    self.logger.debug(f"RDAP timeout for {domain}")
                except Exception as e:
                    self.logger.debug(f"RDAP lookup error: {e}")

        if results:
            self.logger.info(f"WHOIS/RDAP: Found {len(results)} contact(s)")
        
        return results

    async def search_hibp(
        self,
        domain: str,
        api_key: Optional[str] = None,
    ) -> List[str]:
        """
        Search Have I Been Pwned for breached emails from domain.
        Requires paid API key ($3.50/month) for domain search.

        Args:
            domain: Target domain to search
            api_key: HIBP API key (required for domain search)

        Returns:
            List of breached email addresses
        """
        if not api_key:
            self.logger.debug("HIBP: No API key provided, skipping")
            return []

        self.logger.debug(f"Searching HIBP for breached {domain} emails")
        emails: List[str] = []

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                url = f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}"
                headers = {
                    "hibp-api-key": api_key,
                    "User-Agent": "RedSurface-OSINT/1.0",
                }
                
                response = await client.get(url, headers=headers)
                
                if response.status_code == 200:
                    data = response.json()
                    # Response is {email_alias: [breach_names]}
                    for alias in data.keys():
                        email = f"{alias}@{domain}".lower()
                        emails.append(email)
                    
                    if emails:
                        self.logger.info(f"HIBP: Found {len(emails)} breached email(s)")

                elif response.status_code == 401:
                    self.logger.warning("HIBP: Invalid API key")
                elif response.status_code == 404:
                    self.logger.debug(f"HIBP: No breaches found for {domain}")
                elif response.status_code == 429:
                    self.logger.warning("HIBP: Rate limit exceeded")

            except httpx.TimeoutException:
                self.logger.debug(f"HIBP timeout for {domain}")
            except Exception as e:
                self.logger.debug(f"HIBP search error: {e}")

        return emails

    def generate_email_permutations(
        self,
        names: List[Dict[str, str]],
        domain: str,
    ) -> List[str]:
        """
        Generate email permutations from discovered names.
        Common corporate patterns for red team targeting.

        Args:
            names: List of {"first": "John", "last": "Doe"} dicts
            domain: Target domain

        Returns:
            List of potential email addresses
        """
        emails: List[str] = []
        
        for name in names:
            first = name.get("first", "").lower().strip()
            last = name.get("last", "").lower().strip()
            
            if not first and not last:
                continue
            
            for pattern in self.EMAIL_PATTERNS:
                try:
                    email = pattern.format(
                        first=first,
                        last=last,
                        f=first[0] if first else "",
                        l=last[0] if last else "",
                    ) + f"@{domain}"
                    
                    # Skip malformed emails
                    if email.startswith("@") or ".@" in email or "@@" in email:
                        continue
                        
                    emails.append(email.lower())
                except (IndexError, KeyError):
                    continue
        
        # Remove duplicates while preserving order
        seen = set()
        unique_emails = []
        for email in emails:
            if email not in seen:
                seen.add(email)
                unique_emails.append(email)
        
        if unique_emails:
            self.logger.debug(f"Generated {len(unique_emails)} email permutations")
        
        return unique_emails

    async def extract_dns_email_hints(self, domain: str) -> Dict[str, Any]:
        """
        Extract email infrastructure hints from DNS records.
        Useful for understanding mail setup and finding admin contacts.

        Args:
            domain: Target domain

        Returns:
            Dictionary with MX, SPF, DMARC information
        """
        hints: Dict[str, Any] = {
            "mx_records": [],
            "spf_includes": [],
            "spf_record": None,
            "dmarc_email": None,
            "dmarc_record": None,
            "mail_provider": None,
        }

        if not DNS_AVAILABLE:
            self.logger.debug("DNS library not available, skipping DNS hints")
            return hints

        self.logger.debug(f"Extracting DNS email hints for {domain}")

        try:
            resolver = dns.asyncresolver.Resolver()
            # Use system DNS or public DNS based on configuration
            if not self.use_system_dns:
                resolver.nameservers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
            # System DNS uses default nameservers from /etc/resolv.conf or Windows DNS
            resolver.timeout = 3.0  # Shorter timeout for OSINT DNS queries
            resolver.lifetime = 5.0  # Faster failure for non-critical lookups

            # MX records
            try:
                mx_answers = await resolver.resolve(domain, "MX")
                for rdata in mx_answers:
                    mx_host = str(rdata.exchange).rstrip('.')
                    hints["mx_records"].append({
                        "host": mx_host,
                        "priority": rdata.preference,
                    })
                
                # Detect mail provider from MX
                if hints["mx_records"]:
                    mx_host = hints["mx_records"][0]["host"].lower()
                    if "google" in mx_host or "gmail" in mx_host:
                        hints["mail_provider"] = "Google Workspace"
                    elif "outlook" in mx_host or "microsoft" in mx_host:
                        hints["mail_provider"] = "Microsoft 365"
                    elif "protonmail" in mx_host:
                        hints["mail_provider"] = "ProtonMail"
                    elif "zoho" in mx_host:
                        hints["mail_provider"] = "Zoho Mail"
                    elif "mimecast" in mx_host:
                        hints["mail_provider"] = "Mimecast"
                    elif "barracuda" in mx_host:
                        hints["mail_provider"] = "Barracuda"
                        
            except Exception as e:
                self.logger.debug(f"MX lookup failed: {e}")

            # SPF record (TXT)
            try:
                txt_answers = await resolver.resolve(domain, "TXT")
                for rdata in txt_answers:
                    txt = str(rdata).strip('"')
                    if "v=spf1" in txt:
                        hints["spf_record"] = txt
                        # Extract includes (reveals third-party services)
                        includes = re.findall(r'include:(\S+)', txt)
                        hints["spf_includes"] = includes
                        break
            except Exception as e:
                self.logger.debug(f"SPF lookup failed: {e}")

            # DMARC record
            try:
                dmarc_answers = await resolver.resolve(f"_dmarc.{domain}", "TXT")
                for rdata in dmarc_answers:
                    txt = str(rdata).strip('"')
                    if "v=DMARC1" in txt:
                        hints["dmarc_record"] = txt
                        # Extract rua/ruf emails (aggregate/forensic reports)
                        rua_match = re.search(r'rua=mailto:([^\s;,]+)', txt)
                        if rua_match:
                            hints["dmarc_email"] = rua_match.group(1)
                        break
            except Exception as e:
                self.logger.debug(f"DMARC lookup failed: {e}")

            if hints["mx_records"] or hints["spf_record"]:
                self.logger.info(
                    f"DNS hints: {len(hints['mx_records'])} MX, "
                    f"SPF includes: {len(hints['spf_includes'])}, "
                    f"Provider: {hints['mail_provider'] or 'Unknown'}"
                )

        except Exception as e:
            self.logger.debug(f"DNS hints extraction failed: {e}")

        return hints

    async def verify_email(
        self,
        email: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Verify email validity using emailrep.io (free tier: 500/day).
        Returns verification status and reputation data.

        Args:
            email: Email address to verify

        Returns:
            Dictionary with verification results or None
        """
        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                url = f"https://emailrep.io/{email}"
                headers = {
                    "User-Agent": "RedSurface-OSINT/1.0",
                    "Accept": "application/json",
                }
                
                response = await client.get(url, headers=headers)
                
                if response.status_code == 200:
                    data = response.json()
                    return {
                        "email": email,
                        "reputation": data.get("reputation", "unknown"),
                        "suspicious": data.get("suspicious", False),
                        "deliverable": data.get("details", {}).get("deliverable", None),
                        "profiles": data.get("details", {}).get("profiles", []),
                        "blacklisted": data.get("details", {}).get("blacklisted", False),
                        "malicious_activity": data.get("details", {}).get("malicious_activity", False),
                        "credentials_leaked": data.get("details", {}).get("credentials_leaked", False),
                        "data_breach": data.get("details", {}).get("data_breach", False),
                    }
                elif response.status_code == 429:
                    self.logger.debug("EmailRep.io rate limit reached")
                    
            except Exception as e:
                self.logger.debug(f"Email verification failed for {email}: {e}")
        
        return None

    async def verify_emails_batch(
        self,
        emails: List[str],
        max_emails: int = 25,
    ) -> List[Dict[str, Any]]:
        """
        Verify a batch of emails with rate limiting.

        Args:
            emails: List of emails to verify
            max_emails: Maximum emails to verify (to respect rate limits)

        Returns:
            List of verification results for deliverable emails
        """
        verified: List[Dict[str, Any]] = []
        
        self.logger.debug(f"Verifying {min(len(emails), max_emails)} emails...")
        
        for i, email in enumerate(emails[:max_emails]):
            result = await self.verify_email(email)
            if result:
                # Only include if potentially deliverable
                if result.get("deliverable") is not False:
                    verified.append(result)
            
            # Rate limiting - 1 request per second for free tier
            if i < len(emails) - 1:
                await asyncio.sleep(1.0)
        
        if verified:
            self.logger.info(f"Email verification: {len(verified)} potentially valid")
        
        return verified

    async def run(
        self,
        domain: str,
        hunter_key: Optional[str] = None,
        hibp_key: Optional[str] = None,
        generate_permutations: bool = False,
        verify_emails: bool = False,
    ) -> OSINTResults:
        """
        Run all OSINT collection sources and aggregate results.

        Args:
            domain: Target domain to collect OSINT for
            hunter_key: Optional Hunter.io API key
            hibp_key: Optional Have I Been Pwned API key
            generate_permutations: Generate email permutations from names
            verify_emails: Verify discovered emails via emailrep.io

        Returns:
            Aggregated OSINTResults with unique emails and people
        """
        self.logger.info(f"Starting enhanced OSINT collection for {domain}")
        results = OSINTResults()
        all_people: List[PersonInfo] = []
        additional_emails: Set[str] = set()
        
        # Track which sources were queried
        sources = []

        # ===== PHASE 1: Core email sources (parallel) =====
        try:
            pgp_task = self.search_pgp(domain)
            github_task = self.search_github(domain)
            hunter_task = self.search_hunter(domain, hunter_key)
            crtsh_task = self.search_crtsh(domain)
            phonebook_task = self.search_phonebook(domain)
            skymem_task = self.search_skymem(domain)
            whois_task = self.search_whois_contacts(domain)
            
            (
                pgp_results,
                github_results,
                hunter_results,
                crtsh_emails,
                phonebook_emails,
                skymem_emails,
                whois_results,
            ) = await asyncio.gather(
                pgp_task,
                github_task,
                hunter_task,
                crtsh_task,
                phonebook_task,
                skymem_task,
                whois_task,
                return_exceptions=True,
            )
            
            # Process PGP results
            sources.append("PGP Key Servers")
            if isinstance(pgp_results, list):
                all_people.extend(pgp_results)
            elif isinstance(pgp_results, Exception):
                results.errors.append(f"PGP search failed: {pgp_results}")
            
            # Process GitHub results
            sources.append("GitHub API")
            if isinstance(github_results, list):
                all_people.extend(github_results)
            elif isinstance(github_results, Exception):
                results.errors.append(f"GitHub search failed: {github_results}")
            
            # Process Hunter.io results
            if hunter_key:
                sources.append("Hunter.io API")
                if isinstance(hunter_results, list):
                    all_people.extend(hunter_results)
                elif isinstance(hunter_results, Exception):
                    results.errors.append(f"Hunter.io search failed: {hunter_results}")
            
            # Process crt.sh results
            sources.append("crt.sh (Certificate Transparency)")
            if isinstance(crtsh_emails, list):
                for email in crtsh_emails:
                    additional_emails.add(email.lower())
            elif isinstance(crtsh_emails, Exception):
                results.errors.append(f"crt.sh search failed: {crtsh_emails}")

            # Process Phonebook.cz results
            sources.append("Phonebook.cz")
            if isinstance(phonebook_emails, list):
                for email in phonebook_emails:
                    additional_emails.add(email.lower())
            elif isinstance(phonebook_emails, Exception):
                results.errors.append(f"Phonebook.cz search failed: {phonebook_emails}")

            # Process Skymem results
            sources.append("Skymem")
            if isinstance(skymem_emails, list):
                for email in skymem_emails:
                    additional_emails.add(email.lower())
            elif isinstance(skymem_emails, Exception):
                results.errors.append(f"Skymem search failed: {skymem_emails}")

            # Process WHOIS/RDAP results
            sources.append("WHOIS/RDAP")
            if isinstance(whois_results, list):
                all_people.extend(whois_results)
            elif isinstance(whois_results, Exception):
                results.errors.append(f"WHOIS lookup failed: {whois_results}")

        except Exception as e:
            self.logger.error(f"OSINT collection error: {e}")
            results.errors.append(str(e))

        # ===== PHASE 2: HIBP breach search (if API key provided) =====
        if hibp_key:
            sources.append("Have I Been Pwned")
            try:
                hibp_emails = await self.search_hibp(domain, hibp_key)
                for email in hibp_emails:
                    additional_emails.add(email.lower())
                    all_people.append(PersonInfo(
                        email=email.lower(),
                        name="Unknown",
                        role="Breached Account",
                        source="Have I Been Pwned",
                    ))
            except Exception as e:
                results.errors.append(f"HIBP search failed: {e}")

        # ===== PHASE 3: DNS email infrastructure hints =====
        sources.append("DNS Records (MX/SPF/DMARC)")
        try:
            dns_hints = await self.extract_dns_email_hints(domain)
            results.dns_hints = dns_hints
            
            # Add DMARC email if found
            if dns_hints.get("dmarc_email"):
                additional_emails.add(dns_hints["dmarc_email"].lower())
        except Exception as e:
            results.errors.append(f"DNS hints extraction failed: {e}")

        # ===== Deduplicate and aggregate =====
        seen_emails: Set[str] = set()
        
        # First, add people with emails
        for person in all_people:
            if person.email:
                email_lower = person.email.lower()
                if email_lower not in seen_emails:
                    seen_emails.add(email_lower)
                    results.emails.add(email_lower)
                    results.people.append(person)

        # Add additional emails (from sources that don't provide person info)
        for email in additional_emails:
            if email not in seen_emails:
                seen_emails.add(email)
                results.emails.add(email)
                results.people.append(PersonInfo(
                    email=email,
                    name="Unknown",
                    role="Unknown",
                    source="Multiple Sources",
                ))

        # ===== PHASE 4: Email permutation generation =====
        if generate_permutations and results.people:
            sources.append("Email Permutation Generator")
            
            # Extract names for permutation
            names_for_permutation = []
            for person in results.people:
                if person.name and person.name != "Unknown":
                    name_parts = person.name.split()
                    if len(name_parts) >= 2:
                        names_for_permutation.append({
                            "first": name_parts[0],
                            "last": name_parts[-1],
                        })
            
            if names_for_permutation:
                permuted_emails = self.generate_email_permutations(
                    names_for_permutation, domain
                )
                
                # Add new permuted emails (don't add duplicates)
                new_permutations = 0
                for email in permuted_emails:
                    if email not in seen_emails:
                        seen_emails.add(email)
                        results.emails.add(email)
                        new_permutations += 1
                
                if new_permutations:
                    self.logger.info(
                        f"Added {new_permutations} email permutations "
                        f"from {len(names_for_permutation)} names"
                    )

        # ===== PHASE 5: Email verification (optional) =====
        if verify_emails and results.emails:
            sources.append("EmailRep.io Verification")
            try:
                # Verify a subset of discovered emails
                emails_to_verify = list(results.emails)[:25]
                verified = await self.verify_emails_batch(emails_to_verify)
                results.verified_emails = verified
            except Exception as e:
                results.errors.append(f"Email verification failed: {e}")

        results.sources_queried = sources

        # Summary
        self.logger.info(
            f"OSINT collection complete: {len(results.emails)} unique emails, "
            f"{len(results.people)} people identified from {len(sources)} sources"
        )

        return results
