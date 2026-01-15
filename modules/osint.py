"""
OSINT Collection Module for RedSurface.
Collects email addresses and employee data from multiple public sources.
"""

import asyncio
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
import httpx

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
    
    def to_dict(self) -> dict:
        """Convert to dictionary representation."""
        return {
            "emails": sorted(list(self.emails)),
            "people": [p.to_dict() for p in self.people],
            "sources_queried": self.sources_queried,
            "errors": self.errors,
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

    def __init__(
        self,
        timeout: float = 15.0,
        max_retries: int = 2,
        github_token: Optional[str] = None,
    ) -> None:
        """
        Initialize the OSINT collector.

        Args:
            timeout: HTTP request timeout in seconds
            max_retries: Maximum retry attempts for failed requests
            github_token: Optional GitHub personal access token for higher rate limits
        """
        self.timeout = timeout
        self.max_retries = max_retries
        self.github_token = github_token
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

    async def run(
        self,
        domain: str,
        hunter_key: Optional[str] = None,
    ) -> OSINTResults:
        """
        Run all OSINT collection sources and aggregate results.

        Args:
            domain: Target domain to collect OSINT for
            hunter_key: Optional Hunter.io API key

        Returns:
            Aggregated OSINTResults with unique emails and people
        """
        self.logger.info(f"Starting OSINT collection for {domain}")
        results = OSINTResults()
        all_people: List[PersonInfo] = []
        
        # Track which sources were queried
        sources = []

        # Run all searches concurrently
        try:
            pgp_task = self.search_pgp(domain)
            github_task = self.search_github(domain)
            hunter_task = self.search_hunter(domain, hunter_key)
            crtsh_task = self.search_crtsh(domain)
            
            pgp_results, github_results, hunter_results, crtsh_emails = await asyncio.gather(
                pgp_task,
                github_task,
                hunter_task,
                crtsh_task,
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
                    if email not in results.emails:
                        results.emails.add(email)
                        all_people.append(PersonInfo(
                            email=email,
                            name="Unknown",
                            role="Certificate Contact",
                            source="crt.sh",
                        ))
            elif isinstance(crtsh_emails, Exception):
                results.errors.append(f"crt.sh search failed: {crtsh_emails}")

        except Exception as e:
            self.logger.error(f"OSINT collection error: {e}")
            results.errors.append(str(e))

        # Deduplicate and aggregate
        seen_emails: Set[str] = set()
        for person in all_people:
            if person.email:
                email_lower = person.email.lower()
                if email_lower not in seen_emails:
                    seen_emails.add(email_lower)
                    results.emails.add(email_lower)
                    results.people.append(person)

        results.sources_queried = sources

        # Summary
        self.logger.info(
            f"OSINT collection complete: {len(results.emails)} unique emails, "
            f"{len(results.people)} people identified"
        )

        return results
