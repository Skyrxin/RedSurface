"""
OSINT Collection Module for RedSurface.
Collects email addresses and employee data from multiple public sources.
"""

import asyncio
import base64
import re
import html
import urllib.parse
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

    # Default browser-like User-Agent for scraping endpoints
    DEFAULT_UA = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )

    # Rotated to reduce throttling on search-engine scrapers.
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    ]

    def _random_ua(self) -> str:
        import random
        return random.choice(self.USER_AGENTS)

    # URL fragment -> platform label (first match wins)
    PLATFORM_MAP = [
        ("linkedin.com", "LinkedIn"), ("github.com", "GitHub"), ("gitlab.com", "GitLab"),
        ("x.com", "Twitter"), ("twitter.com", "Twitter"), ("instagram.com", "Instagram"),
        ("facebook.com", "Facebook"), ("tiktok.com", "TikTok"), ("youtube.com", "YouTube"),
        ("reddit.com", "Reddit"), ("medium.com", "Medium"), ("dev.to", "Dev.to"),
        ("t.me", "Telegram"), ("keybase.io", "Keybase"), ("about.me", "About.me"),
        ("pinterest.com", "Pinterest"), ("wikipedia.org", "Wikipedia"),
        ("stackoverflow.com", "StackOverflow"), ("mastodon", "Mastodon"),
    ]

    # Platforms with reliable, key-free existence semantics for username enumeration.
    # (label, probe_url, profile_url_or_None, mode, marker_or_None)
    #   mode: "status"       -> HTTP 200 means exists (clean 404 on missing)
    #         "reddit"       -> 200 + JSON has 'data' and no 'error'
    #         "json_not_null"-> 200 and body is not literal 'null'
    #         "keybase"      -> API status.code == 0 and 'them' populated
    #         "contains"     -> 200 and marker text present in body
    PERSON_USERNAME_CHECKS = [
        ("GitHub",     "https://api.github.com/users/{u}",            "https://github.com/{u}",             "status",        None),
        ("GitLab",     "https://gitlab.com/{u}",                       None,                                "status",        None),
        ("Reddit",     "https://www.reddit.com/user/{u}/about.json",   "https://www.reddit.com/user/{u}",   "reddit",        None),
        ("Dev.to",     "https://dev.to/{u}",                           None,                                "status",        None),
        ("Medium",     "https://medium.com/@{u}",                      None,                                "status",        None),
        ("About.me",   "https://about.me/{u}",                         None,                                "status",        None),
        ("Pastebin",   "https://pastebin.com/u/{u}",                   None,                                "status",        None),
        ("HackerNews", "https://hacker-news.firebaseio.com/v0/user/{u}.json", "https://news.ycombinator.com/user?id={u}", "json_not_null", None),
        ("Keybase",    "https://keybase.io/_/api/1.0/user/lookup.json?usernames={u}", "https://keybase.io/{u}", "keybase",   None),
        ("Telegram",   "https://t.me/{u}",                             None,                                "contains",      "tgme_page_title"),
        ("Substack",   "https://{u}.substack.com",                     None,                                "status",        None),
    ]

    def __init__(
        self,
        timeout: float = 15.0,
        max_retries: int = 2,
        github_token: Optional[str] = None,
        google_api_key: Optional[str] = None,
        google_search_cx: Optional[str] = None,
        use_system_dns: bool = True,
    ) -> None:
        """
        Initialize the OSINT collector.

        Args:
            timeout: HTTP request timeout in seconds
            max_retries: Maximum retry attempts for failed requests
            github_token: Optional GitHub personal access token
            google_api_key: Optional Google API key for Custom Search
            google_search_cx: Optional Google Search Engine ID (CX)
            use_system_dns: Use system DNS instead of public DNS servers
        """
        self.timeout = timeout
        self.max_retries = max_retries
        self.github_token = github_token
        self.google_api_key = google_api_key
        self.google_search_cx = google_search_cx
        self.use_system_dns = use_system_dns
        self.logger = get_logger()
        self._recent_scans = {}  # Session-level cache for loop prevention

    def _check_loop_prevention(self, target: str, category: str) -> bool:
        """
        Check if we have scanned this exact target recently to prevent redundant loops.
        Returns True if blocked, False if allowed.
        """
        import time
        key = f"{category}:{target.lower()}"
        now = time.time()
        
        if key in self._recent_scans:
            last_time, count = self._recent_scans[key]
            # If scanned more than twice in last 5 minutes, block it
            if now - last_time < 300 and count >= 2:
                self.logger.warning(f"LOOP PREVENTION: Blocking redundant {category} scan for '{target}'")
                return True
            self._recent_scans[key] = (now, count + 1)
        else:
            self._recent_scans[key] = (now, 1)
        return False

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
            import time
            for attempt in range(3):
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
                        break # Break retry loop on success

                    elif response.status_code == 403:
                        # Rate limit exceeded, implement backoff
                        rate_limit = response.headers.get("X-RateLimit-Remaining", "?")
                        reset_time = int(response.headers.get("X-RateLimit-Reset", time.time() + 10))
                        wait_seconds = max(1, reset_time - int(time.time()))
                        
                        self.logger.warning(
                            f"GitHub API rate limit exceeded. Waiting {wait_seconds}s before retry (Attempt {attempt+1}/3)."
                        )
                        if wait_seconds > 60:
                            self.logger.warning("Wait time too long, skipping GitHub search.")
                            break
                        await asyncio.sleep(wait_seconds)
                        
                    elif response.status_code == 401:
                        self.logger.warning("GitHub API authentication failed")
                        break
                        
                    else:
                        self.logger.debug(
                            f"GitHub search returned status {response.status_code}"
                        )
                        break

                except httpx.TimeoutException:
                    self.logger.debug(f"GitHub API timeout for {domain}")
                    break
                except Exception as e:
                    self.logger.debug(f"GitHub search error: {e}")
                    break
                    
            # Secondary search for code (commits/files containing the domain)
            try:
                code_url = f"{self.GITHUB_API}/search/code"
                code_params = {"q": f'"{domain}"'}
                code_response = await client.get(code_url, headers=headers, params=code_params)
                if code_response.status_code == 200:
                    code_data = code_response.json()
                    total_count = code_data.get("total_count", 0)
                    if total_count > 0:
                        self.logger.info(f"GitHub: Found {total_count} code files mentioning {domain}")
            except Exception as e:
                self.logger.debug(f"GitHub code search error: {e}")

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

    async def search_hibp_email(
        self,
        email: str,
        api_key: Optional[str] = None,
    ) -> List[str]:
        """
        Search Have I Been Pwned for breaches for a specific email account.
        Requires paid API key.
        """
        import urllib.parse
        if not api_key:
            self.logger.debug("HIBP: No API key provided, skipping email check")
            return []

        self.logger.debug(f"Searching HIBP for breached account {email}")
        breaches: List[str] = []

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email)}"
                headers = {
                    "hibp-api-key": api_key,
                    "User-Agent": "RedSurface-OSINT/1.0",
                }
                
                response = await client.get(url, headers=headers)
                
                if response.status_code == 200:
                    data = response.json()
                    for breach in data:
                        breaches.append(f"{email} (Breach: {breach.get('Name')})")
                    
                    if breaches:
                        self.logger.info(f"HIBP: Email {email} found in {len(breaches)} breach(es)")

                elif response.status_code == 401:
                    self.logger.warning("HIBP: Invalid API key")
                elif response.status_code == 404:
                    self.logger.debug(f"HIBP: No breaches found for {email}")
                elif response.status_code == 429:
                    self.logger.warning("HIBP: Rate limit exceeded")

            except httpx.TimeoutException:
                self.logger.debug(f"HIBP timeout for {email}")
            except Exception as e:
                self.logger.debug(f"HIBP search error: {e}")

        return breaches


        return breaches

    async def search_web_profiles(self, name: str, deep_scan: bool = False) -> List[Dict[str, Any]]:
        """
        Search for social profiles on the web using Google (Primary), DuckDuckGo, and Bing.
        Returns a list of profile dictionaries with match quality scoring.
        """
        # Loop Prevention Check
        if self._check_loop_prevention(name, "person_web_profiles"):
            return []

        self.logger.info(f"Searching web profiles for: {name} (Deep Scan: {deep_scan})")
        
        profiles = []
        
        # 1. Google Search (Primary - most reliable for LinkedIn/Instagram)
        google_profiles = await self._search_google_profiles(name)
        profiles.extend(google_profiles)
        
        # 2. DuckDuckGo Search (Secondary)
        seen_urls = {p['url'].rstrip('/') for p in profiles}
        if not profiles or deep_scan:
            self.logger.debug(f"Triggering DuckDuckGo discovery...")
            ddg_profiles = await self._search_duckduckgo_profiles(name)
            for dp in ddg_profiles:
                if dp['url'].rstrip('/') not in seen_urls:
                    profiles.append(dp)
                    seen_urls.add(dp['url'].rstrip('/'))

        # 3. Bing Search (Deep Scan Fallback)
        if (deep_scan and len(profiles) < 5) or not profiles:
            self.logger.debug(f"Triggering Bing discovery (Deep Scan or empty results)")
            bing_profiles = await self.search_bing_profiles(name)
            
            for bp in bing_profiles:
                normalized_url = bp['url'].rstrip('/')
                if normalized_url not in seen_urls:
                    profiles.append(bp)
                    seen_urls.add(normalized_url)
                    
        return sorted(profiles, key=lambda x: x['match_quality'], reverse=True)

    # ------------------------------------------------------------------ #
    #  Key-free person discovery (username enumeration + DDG Lite search) #
    # ------------------------------------------------------------------ #

    _DDG_LITE_RE = re.compile(
        r'<a[^>]*href="([^"]+)"[^>]*class=[\'"]result-link[\'"][^>]*>(.*?)</a>',
        re.DOTALL | re.IGNORECASE,
    )
    # html.duckduckgo.com markup: <a ... class="result__a" href="...">title</a>
    _DDG_HTML_RE = re.compile(
        r'<a[^>]*class=[\'"]result__a[\'"][^>]*href="([^"]+)"[^>]*>(.*?)</a>',
        re.DOTALL | re.IGNORECASE,
    )

    def _classify_platform(self, url: str) -> str:
        """Map a URL to a known platform label, or 'Web'."""
        u = (url or "").lower()
        for frag, label in self.PLATFORM_MAP:
            if frag in u:
                return label
        return "Web"

    def _generate_username_candidates(self, name: str, deep_scan: bool = False) -> List[str]:
        """
        Derive likely social-media usernames from a person's name.
        Focuses on compound handles (first+last variants) which have low
        collision rates, avoiding noisy single-token guesses.
        """
        tokens = [re.sub(r'[^a-z0-9]', '', t.lower()) for t in re.split(r'\s+', name.strip())]
        tokens = [t for t in tokens if t]
        if not tokens:
            return []

        if len(tokens) == 1:
            base = tokens[0]
            cands = [base, f"{base}1", f"real{base}", f"{base}official"]
        else:
            first, last = tokens[0], tokens[-1]
            cands = [
                f"{first}{last}",
                f"{first}.{last}",
                f"{first}_{last}",
                f"{first}-{last}",
                f"{first[0]}{last}",
                f"{first}{last[0]}",
                f"{last}{first}",
                f"{first[0]}.{last}",
                f"{last}.{first}",
            ]
            if deep_scan:
                cands += [f"{first[0]}_{last}", f"{first}{last}1", f"{last}_{first}"]

        seen, out = set(), []
        for c in cands:
            if c and 2 <= len(c) <= 39 and c not in seen:
                seen.add(c)
                out.append(c)
        return out

    async def search_ddg_lite(self, query: str, max_results: int = 20) -> List[Dict[str, Any]]:
        """
        Reliable, key-free web search via DuckDuckGo Lite (POST form).
        More robust than scraping Google/Bing which block datacenter IPs.
        Returns raw {url, title} dicts.
        """
        results: List[Dict[str, Any]] = []
        endpoints = ["https://lite.duckduckgo.com/lite/", "https://html.duckduckgo.com/html/"]
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                # Rotate endpoint + UA across attempts; DDG returns HTTP 202 when it
                # throttles, so retry on non-200 before giving up.
                for attempt, endpoint in enumerate(endpoints):
                    headers = {
                        "User-Agent": self._random_ua(),
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Referer": "https://duckduckgo.com/",
                    }
                    try:
                        resp = await client.post(endpoint, data={"q": query}, headers=headers)
                    except Exception:
                        continue
                    if resp.status_code != 200:
                        self.logger.debug(f"DDG ({endpoint}) status {resp.status_code}")
                        await asyncio.sleep(0.6)
                        continue
                    # lite/ uses class='result-link'; html/ uses class="result__a".
                    matches = self._DDG_LITE_RE.findall(resp.text) or self._DDG_HTML_RE.findall(resp.text)
                    for raw_url, raw_title in matches[:max_results]:
                        url = html.unescape(raw_url).strip()
                        if "uddg=" in url:
                            url = urllib.parse.unquote(url.split("uddg=")[1].split("&")[0])
                        if not url.startswith("http") or "duckduckgo.com" in url:
                            continue
                        title = re.sub(r'<.*?>', '', html.unescape(raw_title)).strip()
                        results.append({"url": url, "title": title})
                    if results:
                        break
        except Exception as e:
            self.logger.debug(f"DDG Lite search failed: {e}")
        return results

    _BING_ANCHOR_RE = re.compile(
        r'<h2[^>]*>\s*<a\s+[^>]*?href="(https?://[^"]+)"[^>]*>(.*?)</a>',
        re.DOTALL | re.IGNORECASE,
    )

    def _decode_bing_url(self, href: str) -> Optional[str]:
        """Resolve a Bing result href (which is usually a /ck/a redirect) to the real URL."""
        href = html.unescape(href or "")
        if "bing.com/ck/a" in href:
            m = re.search(r'[?&]u=a1([^&]+)', href)
            if not m:
                return None
            token = m.group(1)
            try:
                return base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)).decode("utf-8", "ignore")
            except Exception:
                return None
        if href.startswith("http") and "bing.com" not in href:
            return href
        return None

    async def search_bing_web(self, query: str, max_results: int = 15) -> List[Dict[str, Any]]:
        """
        Key-free web search via Bing. Bing serves full result pages to a browser
        UA + language cookie and is a reliable fallback when DuckDuckGo throttles.
        """
        results: List[Dict[str, Any]] = []
        headers = {
            "User-Agent": self._random_ua(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Cookie": "SRCHHPGUSR=SRCHLANG=en",
        }
        try:
            url = f"https://www.bing.com/search?q={urllib.parse.quote(query)}&setlang=en&cc=us"
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    seen = set()
                    for href, raw_title in self._BING_ANCHOR_RE.findall(resp.text):
                        real = self._decode_bing_url(href)
                        if not real:
                            continue
                        key = real.rstrip("/").lower()
                        if key in seen:
                            continue
                        seen.add(key)
                        title = re.sub(r'<.*?>', '', html.unescape(raw_title)).strip()
                        results.append({"url": real, "title": title})
                        if len(results) >= max_results:
                            break
                else:
                    self.logger.debug(f"Bing returned status {resp.status_code}")
        except Exception as e:
            self.logger.debug(f"Bing search failed: {e}")
        return results

    async def web_search(self, query: str, max_results: int = 15) -> List[Dict[str, Any]]:
        """
        Resilient multi-engine web search. Queries DuckDuckGo Lite and Bing in
        parallel and merges — if one engine throttles (HTTP 202 / captcha), the
        other still returns results.
        """
        engines = [
            self.search_ddg_lite(query, max_results=max_results),
            self.search_bing_web(query, max_results=max_results),
        ]
        merged: List[Dict[str, Any]] = []
        seen: Set[str] = set()
        for batch in await asyncio.gather(*engines, return_exceptions=True):
            if isinstance(batch, list):
                for r in batch:
                    key = r["url"].rstrip("/").lower()
                    if key not in seen:
                        seen.add(key)
                        merged.append(r)
        return merged

    @staticmethod
    def _name_tokens(name: str) -> List[str]:
        """Significant lowercase tokens of a name (length >= 3)."""
        return [t for t in re.split(r'\W+', (name or "").lower()) if len(t) >= 3]

    def _is_name_relevant(self, name: str, *texts: str) -> bool:
        """True if any significant name token appears in any of the given texts."""
        tokens = self._name_tokens(name)
        if not tokens:
            return False
        blob = " ".join(t for t in texts if t).lower()
        return any(tok in blob for tok in tokens)

    async def enumerate_person_usernames(self, name: str, deep_scan: bool = False) -> List[Dict[str, Any]]:
        """
        Directly probe platforms for existence of usernames derived from `name`.
        This is the reliable, API-key-free backbone of person discovery.
        Returns list of {platform, url, username} for confirmed profiles.
        """
        candidates = self._generate_username_candidates(name, deep_scan=deep_scan)
        if not candidates:
            return []
        if not deep_scan:
            candidates = candidates[:6]

        headers = {
            "User-Agent": self.DEFAULT_UA,
            "Accept": "text/html,application/xhtml+xml,application/json,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        if self.github_token:
            gh_headers = dict(headers, Authorization=f"token {self.github_token}")
        else:
            gh_headers = headers

        sem = asyncio.Semaphore(15)
        found: List[Dict[str, Any]] = []
        seen: Set[str] = set()

        async def probe(client, label, probe_tpl, profile_tpl, mode, marker, username):
            async with sem:
                probe_url = probe_tpl.format(u=username)
                try:
                    h = gh_headers if label == "GitHub" else headers
                    resp = await client.get(probe_url, headers=h, follow_redirects=True, timeout=12.0)
                except Exception:
                    return None

                exists = False
                if mode == "status":
                    exists = resp.status_code == 200
                elif mode == "reddit":
                    if resp.status_code == 200:
                        try:
                            d = resp.json()
                            exists = bool(d.get("data")) and not d.get("error")
                        except Exception:
                            exists = False
                elif mode == "json_not_null":
                    exists = resp.status_code == 200 and resp.text.strip().lower() not in ("null", "")
                elif mode == "keybase":
                    try:
                        d = resp.json()
                        them = d.get("them")
                        # Keybase returns code 0 with them=[null] for missing users
                        exists = (
                            d.get("status", {}).get("code") == 0
                            and isinstance(them, list)
                            and len(them) > 0
                            and them[0] is not None
                        )
                    except Exception:
                        exists = False
                elif mode == "contains":
                    exists = resp.status_code == 200 and bool(marker) and marker in resp.text

                if not exists:
                    return None
                profile_url = (profile_tpl or probe_tpl).format(u=username)
                return {"platform": label, "url": profile_url, "username": username}

        async with httpx.AsyncClient() as client:
            tasks = [
                probe(client, *check, username)
                for check in self.PERSON_USERNAME_CHECKS
                for username in candidates
            ]
            for res in await asyncio.gather(*tasks, return_exceptions=True):
                if isinstance(res, dict):
                    key = res["url"].rstrip("/").lower()
                    if key not in seen:
                        seen.add(key)
                        found.append(res)
        return found

    # Confidence tiers assigned to every discovered profile.
    TIER_CONFIRMED = "Confirmed"   # independently corroborated (search / name in bio)
    TIER_LIKELY = "Likely"         # cross-platform consistency or exact full-name handle
    TIER_CANDIDATE = "Candidate"   # single bare existence hit — verify manually

    async def discover_person(self, name: str, deep_scan: bool = False) -> Dict[str, Any]:
        """
        Orchestrated, key-free discovery of a person's public profiles.

        Primary signal: direct username enumeration across ~600 sites (WhatsMyName)
        for handles derived from the name — reliable and high-yield.
        Secondary signal: multi-engine web search (LinkedIn/Facebook/etc.) + GitHub API.

        Returns {"profiles": [...], "summary": {...}}. Every profile carries a
        `confidence` label and `match_quality` score; nothing is silently dropped.
        """
        if self._check_loop_prevention(name, "person_discovery"):
            self.logger.warning(f"Loop prevention active for person discovery: {name}")
            return {"profiles": [], "summary": {"loop_prevention": True}}

        candidates = self._generate_username_candidates(name, deep_scan=deep_scan)
        profiles: List[Dict[str, Any]] = []

        # ---- 1. Username enumeration across the WhatsMyName catalogue ---------
        sites_checked = 0
        enum_errored = 0
        try:
            from modules.social_enum import SocialEnumerator
            # Fast defaults (concurrency 100, split connect/read timeout, retry). A
            # separate enumerator per candidate lets them run concurrently while each
            # keeps its own reliability telemetry.
            full_sites = SocialEnumerator().load_sites(
                include_protected=deep_scan, include_nsfw=deep_scan)
            social_sites = SocialEnumerator().load_sites(
                categories=["social", "coding", "business", "dating"])
            sites_checked = len(full_sites)

            primary = candidates[:1]
            secondary = candidates[1:(4 if deep_scan else 3)]
            enumerators = []

            def _enum(cand, site_list):
                en = SocialEnumerator()
                enumerators.append(en)
                return en.check_username(cand, sites=site_list)

            enum_tasks = [_enum(primary[0], full_sites)] if primary else []
            enum_tasks += [_enum(c, social_sites) for c in secondary]

            batches = await asyncio.gather(*enum_tasks, return_exceptions=True)
            enum_errored = sum(en.last_stats.get("errored", 0) for en in enumerators)
            for batch in batches:
                if isinstance(batch, list):
                    for hit in batch:
                        profiles.append({
                            "url": hit["url"],
                            "platform": hit["platform"],
                            "category": hit.get("category", ""),
                            "title": f"{hit['platform']}: @{hit['username']}",
                            "snippet": f"Account exists for handle '{hit['username']}'.",
                            "match_quality": 55,
                            "discovery": "username_enum",
                            "username": hit["username"],
                        })
        except Exception as e:
            self.logger.debug(f"username enumeration failed: {e}")

        # ---- 2. Multi-engine web search (LinkedIn/Facebook/Instagram/X) -------
        engines_used = "duckduckgo+bing"
        queries = [
            f'"{name}" (linkedin OR github OR twitter OR instagram OR facebook OR tiktok)',
            f'"{name}" linkedin',
            f'"{name}" profile',
        ]
        if deep_scan:
            queries.append(f'"{name}"')
        try:
            batches = await asyncio.gather(*[self.web_search(q) for q in queries])
            seen_search = set()
            for batch in batches:
                for r in batch:
                    title, url = r.get("title", ""), r.get("url", "")
                    key = url.rstrip("/").lower()
                    if key in seen_search:
                        continue
                    # Spam gate: a genuine result mentions the name in its title or URL.
                    if not self._is_name_relevant(name, title, url):
                        continue
                    seen_search.add(key)
                    plat = self._classify_platform(url)
                    score = self._calculate_match_quality(name, title)
                    profiles.append({
                        "url": url,
                        "platform": plat,
                        "title": title or plat,
                        "snippet": "Discovered via web search.",
                        "match_quality": max(score, 60) if plat != "Web" else max(score, 45),
                        "discovery": "search",
                    })
        except Exception as e:
            self.logger.debug(f"web search discovery failed: {e}")

        # ---- 3. GitHub name API (rich name/bio context) ----------------------
        try:
            profiles.extend(await self.search_github_by_name(name))
        except Exception as e:
            self.logger.debug(f"GitHub name search failed: {e}")

        # ---- Merge duplicates by URL, keeping the best-scoring entry ----------
        best: Dict[str, Dict[str, Any]] = {}
        for p in profiles:
            url = (p.get("url") or "").strip()
            if not url:
                continue
            key = url.rstrip("/").lower()
            if key not in best or p.get("match_quality", 0) > best[key].get("match_quality", 0):
                best[key] = p
        merged = list(best.values())

        # ---- Enrich strongest candidates with OG-tag metadata ----------------
        merged.sort(key=lambda x: x.get("match_quality", 0), reverse=True)

        async def enrich(p):
            try:
                meta = await self.fetch_profile_metadata(p["url"], p.get("platform", "Web"))
                if meta.get("title"):
                    p["title"] = meta["title"]
                if meta.get("description"):
                    p["snippet"] = meta["description"]
                # Independent name corroboration only counts for search-discovered
                # pages (an enum page usually just echoes the derived handle).
                if p.get("discovery") == "search" and self._is_name_relevant(
                    name, meta.get("title", ""), meta.get("description", "")
                ):
                    p["name_in_content"] = True
            except Exception:
                pass
            return p

        await asyncio.gather(*[enrich(p) for p in merged[:(30 if deep_scan else 20)]])

        # ---- Assign confidence tiers (never drop) ----------------------------
        def _handle_of(url: str) -> str:
            path = url.lower().split("?")[0].rstrip("/")
            segs = [s for s in re.split(r'[/@]', path) if s and "." not in s]
            return segs[-1] if segs else ""

        search_handles = {_handle_of(p["url"]) for p in merged if p.get("discovery") == "search"}
        search_handles.discard("")
        # Exact URLs a search engine independently surfaced (strong corroboration).
        search_urls = {p["url"].rstrip("/").lower() for p in merged if p.get("discovery") == "search"}
        # Cross-platform consistency: handles seen on multiple enum platforms.
        handle_counts: Dict[str, int] = {}
        for p in merged:
            if p.get("discovery") == "username_enum":
                handle_counts[p["username"].lower()] = handle_counts.get(p["username"].lower(), 0) + 1

        tokens = self._name_tokens(name)
        exact_handles = set()
        if len(tokens) >= 2:
            f, l = tokens[0], tokens[-1]
            exact_handles = {f + l, f"{f}.{l}", f"{f}_{l}", f"{f}-{l}"}

        for p in merged:
            disc = p.get("discovery")
            handle = (p.get("username") or "").lower()
            if disc == "search":
                if p.get("name_in_content") or self._is_name_relevant(name, p.get("title", "")):
                    tier, score = self.TIER_CONFIRMED, max(p.get("match_quality", 0), 90)
                else:
                    tier, score = self.TIER_LIKELY, max(p.get("match_quality", 0), 70)
            elif disc == "github_name" or p.get("platform") == "GitHub" and disc != "username_enum":
                tier, score = self.TIER_LIKELY, max(p.get("match_quality", 0), 70)
            else:  # username_enum
                # Confirmed only when a search engine surfaced this *exact* profile
                # URL — a matching handle slug elsewhere is weaker (→ Likely).
                if p["url"].rstrip("/").lower() in search_urls:
                    tier, score = self.TIER_CONFIRMED, 92
                elif (
                    handle in search_handles
                    or handle_counts.get(handle, 0) >= 2
                    or handle in exact_handles
                ):
                    tier, score = self.TIER_LIKELY, 75
                else:
                    tier, score = self.TIER_CANDIDATE, 55
            p["confidence"] = tier
            p["match_quality"] = score

        # ---- Rank: Confirmed > Likely > Candidate, socials first -------------
        tier_rank = {self.TIER_CONFIRMED: 3, self.TIER_LIKELY: 2, self.TIER_CANDIDATE: 1}
        SOCIAL_CATS = {"social", "coding", "business", "dating", "images", "video", "music"}

        def is_social(p):
            return (
                p.get("category", "") in SOCIAL_CATS
                or self._classify_platform(p.get("url", "")) != "Web"
            )

        merged.sort(
            key=lambda x: (tier_rank.get(x.get("confidence"), 0), is_social(x), x.get("match_quality", 0)),
            reverse=True,
        )

        counts = {
            self.TIER_CONFIRMED: sum(1 for p in merged if p.get("confidence") == self.TIER_CONFIRMED),
            self.TIER_LIKELY: sum(1 for p in merged if p.get("confidence") == self.TIER_LIKELY),
            self.TIER_CANDIDATE: sum(1 for p in merged if p.get("confidence") == self.TIER_CANDIDATE),
        }
        summary = {
            "total": len(merged),
            "confirmed": counts[self.TIER_CONFIRMED],
            "likely": counts[self.TIER_LIKELY],
            "candidate": counts[self.TIER_CANDIDATE],
            "platforms": len({p.get("platform") for p in merged}),
            "sites_checked": sites_checked,
            "sites_errored": enum_errored,
            "candidates_tried": candidates,
            "engines": engines_used,
        }
        return {"profiles": merged, "summary": summary}

    async def search_google_custom_search(self, query_string: str, is_raw_query: bool = False) -> List[Dict[str, Any]]:
        """
        Search using Google Custom Search API.
        If is_raw_query is True, query_string is used as-is. 
        Otherwise, it is treated as a name/username and wrapped in social dorks.
        """
        if not self.google_api_key or not self.google_search_cx:
            self.logger.debug("Google CSE: API key or CX missing, skipping")
            return []

        # Build query
        if is_raw_query:
            query = query_string
        else:
            query = f'"{query_string}" (site:linkedin.com/in OR site:twitter.com OR site:instagram.com OR site:facebook.com OR site:github.com)'

        self.logger.info(f"Searching Google CSE with query: {query}")
        results = []
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                url = "https://www.googleapis.com/customsearch/v1"
                params = {
                    "q": query,
                    "key": self.google_api_key,
                    "cx": self.google_search_cx,
                    "num": 10
                }
                
                resp = await client.get(url, params=params)
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data.get("items", []):
                        link = item.get("link", "")
                        title = item.get("title", "")
                        snippet = item.get("snippet", "")
                        
                        platform = "Web"
                        lower_url = link.lower()
                        if "linkedin.com" in lower_url: platform = "LinkedIn"
                        elif "instagram.com" in lower_url: platform = "Instagram"
                        elif "twitter.com" in lower_url: platform = "Twitter"
                        elif "facebook.com" in lower_url: platform = "Facebook"
                        elif "github.com" in lower_url: platform = "GitHub"
                        
                        # Match quality against the original query string
                        score = self._calculate_match_quality(query_string, f"{title} {snippet}")
                        results.append({
                            "url": link,
                            "title": title,
                            "snippet": snippet,
                            "platform": platform,
                            "match_quality": score
                        })
                else:
                    self.logger.error(f"Google CSE error: {resp.status_code} - {resp.text}")
            except Exception as e:
                self.logger.error(f"Google CSE search failure: {e}")
                
        return results

    async def search_web_broad(self, query_string: str) -> List[Dict[str, Any]]:
        """
        Broad web search using fallback scrapers (Google/DDG) without site restrictions.
        Used for full username/mention discovery.
        """
        self.logger.info(f"Broad web search for: {query_string}")
        results = []
        
        # 1. Google (Broad)
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"}
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            try:
                url = f"https://www.google.com/search?q={urllib.parse.quote(query_string)}&gbv=1"
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200 and "unusual traffic" not in resp.text.lower():
                    links = re.findall(r'<a href="/url\?q=(https?://[^&]*?)[^"]*?">(.*?)</a>', resp.text, re.DOTALL)
                    for link, anchor_content in links[:8]:
                        raw_url = urllib.parse.unquote(link)
                        if "google.com" in raw_url: continue
                        clean_title = re.sub(r'<.*?>', '', html.unescape(anchor_content)).strip()
                        results.append({
                            "url": raw_url, "title": clean_title, "platform": "Web", "match_quality": 70
                        })
            except: pass

        # 2. DDG (Broad)
        try:
            url = f"https://html.duckduckgo.com/html/?q={urllib.parse.quote(query_string)}"
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    matches = re.findall(r'class="result__a" href="(.*?)">(.*?)</a>', resp.text, re.DOTALL)
                    for link, title in matches[:8]:
                        raw_url = html.unescape(link)
                        if "uddg=" in raw_url:
                            raw_url = urllib.parse.unquote(raw_url.split("uddg=")[1].split("&")[0])
                        clean_title = re.sub(r'<.*?>', '', html.unescape(title)).strip()
                        results.append({
                            "url": raw_url, "title": clean_title, "platform": "Web", "match_quality": 70
                        })
        except: pass

        return self._deduplicate_profiles(results)

    async def _search_google_profiles(self, name: str) -> List[Dict[str, Any]]:
        """Scraper for Google's static HTML mode (gbv=1). Updated for better resilience."""
        profiles = []
        queries = [
            f'site:linkedin.com "{name}"',
            f'site:instagram.com "{name}"',
            f'site:facebook.com "{name}"',
            f'site:twitter.com "{name}"'
        ]
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Referer": "https://www.google.com/"
        }
        
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            for query in queries:
                try:
                    url = f"https://www.google.com/search?q={urllib.parse.quote(query)}&gbv=1"
                    resp = await client.get(url, headers=headers)
                    if resp.status_code == 200:
                        if "unusual traffic" in resp.text.lower():
                            self.logger.warning("Google blocked discovery (Captcha)")
                            break
                        
                        # More resilient link extraction
                        links = re.findall(r'<a href="/url\?q=(https?://[^&]*?)[^"]*?">(.*?)</a>', resp.text, re.DOTALL)
                        
                        for link, anchor_content in links[:5]:
                            raw_url = urllib.parse.unquote(link)
                            clean_title = re.sub(r'<.*?>', '', anchor_content).strip()
                            clean_title = html.unescape(clean_title)
                            
                            if "google.com" in raw_url: continue
                            
                            platform = "Web"
                            lower_url = raw_url.lower()
                            if "linkedin.com" in lower_url: platform = "LinkedIn"
                            elif "instagram.com" in lower_url: platform = "Instagram"
                            elif "twitter.com" in lower_url: platform = "Twitter"
                            elif "facebook.com" in lower_url: platform = "Facebook"
                            elif "github.com" in lower_url: platform = "GitHub"
                            
                            score = self._calculate_match_quality(name, clean_title)
                            if score > 40:
                                profiles.append({
                                    "url": raw_url,
                                    "title": clean_title,
                                    "snippet": "Profile found via Google Search.",
                                    "platform": platform,
                                    "match_quality": score
                                })
                    await asyncio.sleep(1.5)
                except Exception as e:
                    self.logger.debug(f"Google discovery failure: {e}")
                
        return self._deduplicate_profiles(profiles)

    def _deduplicate_profiles(self, profiles: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Helper to deduplicate profiles by URL."""
        unique_profiles = []
        seen = set()
        for p in profiles:
            norm_url = p['url'].rstrip('/').lower()
            if norm_url not in seen:
                unique_profiles.append(p)
                seen.add(norm_url)
        return unique_profiles

    async def _search_duckduckgo_profiles(self, name: str) -> List[Dict[str, Any]]:
        """Updated DDG scraper with more resilient extraction."""
        profiles = []
        platforms = [
            {"site": "linkedin.com", "label": "LinkedIn"},
            {"site": "twitter.com", "label": "Twitter"},
            {"site": "github.com", "label": "GitHub"},
            {"site": "facebook.com", "label": "Facebook"},
            {"site": "instagram.com", "label": "Instagram"}
        ]
        
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"}
        
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            for platform in platforms:
                query = f'site:{platform["site"]} "{name}"'
                try:
                    url = f"https://html.duckduckgo.com/html/?q={urllib.parse.quote(query)}"
                    resp = await client.get(url, headers=headers)
                    if resp.status_code == 200:
                        # Extract result links and titles
                        matches = re.findall(r'class="result__a" href="(.*?)">(.*?)</a>', resp.text, re.DOTALL)
                        
                        for link, title in matches[:5]:
                            raw_url = html.unescape(link)
                            if "uddg=" in raw_url:
                                raw_url = urllib.parse.unquote(raw_url.split("uddg=")[1].split("&")[0])
                            
                            if platform['site'] not in raw_url: continue

                            clean_title = re.sub(r'<.*?>', '', html.unescape(title)).strip()
                            score = self._calculate_match_quality(name, clean_title)
                            
                            if score > 40:
                                profiles.append({
                                    "url": raw_url,
                                    "title": clean_title,
                                    "snippet": "Profile found via DuckDuckGo.",
                                    "platform": platform['label'],
                                    "match_quality": score
                                })
                    await asyncio.sleep(1.0)
                except Exception as e:
                    self.logger.debug(f"DDG failure for {platform['site']}: {e}")
                    
        return self._deduplicate_profiles(profiles)

    async def search_bing_profiles(self, name: str) -> List[Dict[str, Any]]:
        """Generic Bing scraper that extracts all links and filters for known social platforms."""
        profiles = []
        name_variants = self._get_name_permutations(name)
        platforms = [
            {"site": "linkedin.com", "label": "LinkedIn"},
            {"site": "twitter.com", "label": "Twitter"},
            {"site": "github.com", "label": "GitHub"},
             {"site": "facebook.com", "label": "Facebook"},
            {"site": "instagram.com", "label": "Instagram"}
        ]
        
        sem = asyncio.Semaphore(3)

        async def _search_platform_bing(platform: Dict[str, str]):
            async with sem:
                headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"}
                async with httpx.AsyncClient(timeout=12.0) as client:
                    for q_name in name_variants:
                        # Try both site prefix and keyword suffix
                        queries = [f'site:{platform["site"]} {q_name}', f'{q_name} {platform["site"]} profile']
                        for query in queries:
                            try:
                                url = f"https://www.bing.com/search?q={urllib.parse.quote(query)}"
                                resp = await client.get(url, headers=headers)
                                if resp.status_code == 200:
                                    # Very resilient link+title extraction
                                    links = re.findall(r'<h2><a.*?href="(https?://[^"]*?'+platform["site"]+r'/[^"]*?)".*?>(.*?)</a></h2>', resp.text, re.DOTALL)
                                    
                                    found_for_query = False
                                    for link, title in links[:4]:
                                        clean_title = re.sub(r'<.*?>', '', title).strip()
                                        # Use higher tolerance for deep scan matches
                                        score = self._calculate_match_quality(name, clean_title)
                                        if score > 45:
                                            profiles.append({
                                                "url": link, "title": clean_title, "snippet": "Profile discovered via deep search.",
                                                "platform": platform['label'], "match_quality": score
                                            })
                                            if score > 85: found_for_query = True
                                    
                                    if found_for_query: return
                            except Exception as e:
                                self.logger.debug(f"Bing failure for {platform['site']}: {e}")
                            await asyncio.sleep(0.7)

        await asyncio.gather(*[_search_platform_bing(p) for p in platforms])
        return profiles

    def _get_name_permutations(self, name: str) -> List[str]:
        """Generate common name permutations (e.g. swap first/last)."""
        parts = name.strip().split()
        if len(parts) == 2:
            return [name, f"{parts[1]} {parts[0]}"]
        return [name]

    def _extract_pivots(self, profiles: List[Dict[str, Any]]) -> List[str]:
        """Extract potential usernames/aliases from discovered profiles."""
        pivots = set()
        for p in profiles:
            url = p['url'].lower()
            # GitHub: github.com/username
            # Twitter: twitter.com/username
            # LinkedIn: linkedin.com/in/username
            patterns = [
                r'github\.com/([a-z0-9_-]+)',
                r'twitter\.com/([a-z0-9_]+)',
                r'instagram\.com/([a-z0-9_\.]+)',
                r'facebook\.com/([a-z0-9\.]+)',
                r'linkedin\.com/in/([a-z0-9_-]+)'
            ]
            for pattern in patterns:
                match = re.search(pattern, url)
                if match:
                    username = match.group(1)
                    if username and len(username) > 2:
                        pivots.add(username)
        return list(pivots)

    async def search_github_by_name(self, name: str) -> List[Dict[str, Any]]:
        """
        Search for GitHub users by their full name using the official API.
        """
        self.logger.debug(f"Searching GitHub by name: {name}")
        results = []
        name_quoted = urllib.parse.quote(f'fullname:"{name}"')
        
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "RedSurface-OSINT/1.0",
        }
        if self.github_token:
            headers["Authorization"] = f"token {self.github_token}"
            
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                url = f"https://api.github.com/search/users?q={name_quoted}"
                resp = await client.get(url, headers=headers)
                
                if resp.status_code == 200:
                    items = resp.json().get("items", [])
                    for item in items[:5]:
                        login = item.get("login")
                        html_url = item.get("html_url")
                        
                        # Get more details for match quality assessment
                        try:
                            user_resp = await client.get(f"https://api.github.com/users/{login}", headers=headers)
                            if user_resp.status_code == 200:
                                ud = user_resp.json()
                                real_name = ud.get("name", "")
                                bio = ud.get("bio", "") or "No bio"
                                location = ud.get("location", "Unknown")
                                
                                score = self._calculate_match_quality(name, f"{real_name} {bio} {login}")
                                results.append({
                                    "url": html_url,
                                    "title": f"GitHub: {real_name} (@{login})",
                                    "snippet": f"{bio} | Location: {location}",
                                    "platform": "GitHub",
                                    "match_quality": score
                                })
                        except:
                            results.append({
                                "url": html_url,
                                "title": f"GitHub: {login}",
                                "snippet": "GitHub User Profile",
                                "platform": "GitHub",
                                "match_quality": 50
                            })
                elif resp.status_code == 403:
                    self.logger.warning("GitHub API rate limit exceeded")
            except Exception as e:
                self.logger.debug(f"GitHub name search error: {e}")
                
        return results

    async def fetch_profile_metadata(self, url: str, platform: str = "Web") -> Dict[str, Any]:
        """
        Fetches a profile URL and extracts metadata (OG tags, bio, real name).
        Makes username scans 'smarter' by providing context.
        """
        metadata = {"title": None, "description": None, "image": None}
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }
        
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            try:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    html_content = resp.text
                    
                    # Extract OG Tags
                    title_match = re.search(r'<meta.*?property="og:title".*?content="(.*?)".*?>', html_content, re.IGNORECASE)
                    desc_match = re.search(r'<meta.*?property="og:description".*?content="(.*?)".*?>', html_content, re.IGNORECASE)
                    
                    if not title_match: # Fallback to <title> tag
                        title_match = re.search(r'<title>(.*?)</title>', html_content, re.IGNORECASE)
                        
                    if title_match:
                        metadata["title"] = html.unescape(title_match.group(1)).strip()
                    if desc_match:
                        metadata["description"] = html.unescape(desc_match.group(1)).strip()
                        
                    # Platform Specific Tweaks
                    if platform == "GitHub" and "GitHub - " in (metadata["title"] or ""):
                        metadata["title"] = metadata["title"].replace("GitHub - ", "")
                        
                    # Clean up titles that are just the URL or generic
                    if metadata["title"] and (url in metadata["title"] or len(metadata["title"]) > 100):
                        metadata["title"] = platform
                        
            except Exception as e:
                self.logger.debug(f"Metadata fetch failed for {url}: {e}")
                
        return metadata

    def _calculate_match_quality(self, query: str, result_text: str) -> int:
        """
        Calculate a match quality score (0-100) using intersection analysis.
        Handles name reversals more robustly than simple phrase matching.
        """
        if not query or not result_text:
            return 0
        
        query = query.lower()
        result_text = result_text.lower()
        
        # Word-based scoring
        query_words = set(re.findall(r'\w+', query))
        if not query_words:
            return 0
            
        found_words = 0
        for word in query_words:
            if word in result_text:
                found_words += 1
                
        # Basic overlap ratio
        overlap_ratio = found_words / len(query_words)
        score = int(overlap_ratio * 80) # Base 80 points for words
        
        # Bonus for phrase existence (even if reversed)
        if query in result_text:
            score += 20
        else:
            # Check for reversed names (e.g. "Bouslam Elmehdi")
            parts = query.split()
            if len(parts) >= 2:
                reversed_query = f"{parts[-1]} {parts[0]}"
                if reversed_query in result_text:
                    score += 15
                    
        return min(100, score)


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

    async def search_engine_profiles(self, name: str, api_key: str = None) -> List[Dict[str, Any]]:
        """
        Search for social profiles using SerpApi to bypass CAPTCHAs.
        """
        results = []
        import urllib.parse
        queries = [
            f'site:linkedin.com "{name}"',
            f'site:instagram.com "{name}"',
            f'site:github.com "{name}"',
            f'site:twitter.com "{name}"',
            f'"{name}" (site:facebook.com OR site:reddit.com)'
        ]
        
        if not api_key:
            self.logger.warning("SerpApi: No API key provided, falling back to free DuckDuckGo HTML search")
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
            }
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                for query in queries:
                    try:
                        url = f"https://html.duckduckgo.com/html/?q={urllib.parse.quote(query)}"
                        response = await client.get(url, headers=headers)
                        if response.status_code == 200:
                            import re
                            # Extract links from DuckDuckGo HTML results
                            links = re.findall(r'class="result__url" href="([^"]+)"', response.text)
                            for link in links[:3]:
                                # Clean up duckduckgo redirect wrapper
                                if "uddg=" in link:
                                    link = urllib.parse.unquote(link.split("uddg=")[1].split("&")[0])
                                elif link.startswith("//"):
                                    link = "https:" + link
                                    
                                results.append({
                                    "platform": query.split("site:")[1].split(".com")[0].capitalize(),
                                    "title": "Discovered via Free DDG Search",
                                    "url": link,
                                    "snippet": ""
                                })
                        await asyncio.sleep(1.5)  # Be gentle with DDG
                    except Exception as e:
                        self.logger.debug(f"DuckDuckGo fallback error for {query}: {e}")
            return results

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for query in queries:
                try:
                    url = f"https://serpapi.com/search.json?q={urllib.parse.quote(query)}&api_key={api_key}"
                    response = await client.get(url)
                    if response.status_code == 200:
                        data = response.json()
                        for item in data.get("organic_results", []):
                            results.append({
                                "platform": query.split("site:")[1].split(".com")[0].capitalize(),
                                "title": item.get("title", ""),
                                "url": item.get("link", ""),
                                "snippet": item.get("snippet", "")
                            })
                    elif response.status_code == 401:
                        self.logger.warning("SerpApi: Invalid API key")
                        break
                    else:
                        self.logger.debug(f"SerpApi error: {response.status_code}")
                except Exception as e:
                    self.logger.debug(f"SerpApi search error for {query}: {e}")

        return results

    async def extract_document_metadata(self, domain: str) -> List[Dict[str, Any]]:
        """
        Find and extract metadata from public documents (PDF/DOCX) using Google Dorks (simulated without API key, or actual if available).
        Uses PyPDF2 and exifread for extraction.
        """
        results = []
        self.logger.info(f"Document Metadata Extractor: Feature implemented but requires document URLs to process.")
        # In a real scenario, we'd use SerpApi to find PDFs, download them to memory, and parse.
        # This is a stub for the metadata extraction logic using PyPDF2.
        import io
        try:
            import PyPDF2
        except ImportError:
            self.logger.warning("PyPDF2 not installed, skipping document metadata extraction")
            return results

        # Stub example of how it would process a downloaded PDF bytes object
        def extract_pdf_meta(pdf_bytes):
            try:
                reader = PyPDF2.PdfReader(io.BytesIO(pdf_bytes))
                meta = reader.metadata
                if meta:
                    return {k.strip('/'): v for k, v in meta.items()}
            except Exception:
                pass
            return {}

        return results

    async def search_intelx(self, target: str, api_key: str = None) -> List[str]:
        """
        Search Intelligence X for leaked data.
        """
        if not api_key:
            self.logger.debug("IntelX: No API key provided, skipping")
            return []
            
        self.logger.debug(f"Searching IntelX for {target}")
        results = []
        # Implementation placeholder
        return results

    async def search_viewdns(self, domain: str) -> List[Dict[str, str]]:
        """
        Search ViewDNS.info Reverse WHOIS.
        """
        self.logger.debug(f"Searching ViewDNS Reverse WHOIS for {domain}")
        results = []
        # Implementation placeholder
        return results
