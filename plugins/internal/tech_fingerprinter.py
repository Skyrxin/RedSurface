"""
Technology Fingerprinter Plugin — Full wrapper around modules/fingerprint.py.

Exposes the complete Wappalyzer-style detection:
  - HTTP header analysis (Server, X-Powered-By, etc.)
  - Cookie-based detection (PHPSESSID, JSESSIONID, etc.)
  - HTML/JS content analysis (CMS, frameworks, analytics, CDN)
  - WAF detection (Cloudflare, Akamai, Imperva, etc.)
  - NVD CVE lookup for each detected technology

Fingerprints the main target PLUS discovered subdomains for comprehensive
technology and vulnerability mapping across the entire attack surface.
"""
from plugins.base import PluginBase, PluginResult, PluginCategory, ApiType


class TechFingerprinterPlugin(PluginBase):
    name = "Technology Fingerprinter"
    description = (
        "Wappalyzer-style technology detection: identifies web servers, CMS, JS frameworks, "
        "CSS frameworks, analytics, CDN, WAFs, and maps each to known CVEs via NVD. "
        "Scans the main target and up to 15 discovered subdomains."
    )
    category = PluginCategory.INTERNAL
    api_type = ApiType.INTERNAL
    requires_api_key = False
    api_key_names = ["NVD_API_KEY"]
    result_types = ["technology", "vulnerability", "waf"]

    async def run(self, target: str, config: dict = None) -> PluginResult:
        result = PluginResult(plugin_name=self.name, result_type="technology")
        try:
            from modules.fingerprint import TechFingerprinter

            fingerprinter = TechFingerprinter(
                timeout=(config or {}).get("timeout", 10.0),
                max_concurrent=(config or {}).get("max_concurrent", 10),
                follow_redirects=True,
                verify_ssl=False,
                nvd_api_key=self.api_keys.get("NVD_API_KEY"),
                use_nvd=(config or {}).get("use_nvd", True),
            )

            # Build list of hosts to scan: main domain + top subdomains
            hosts_to_scan = [target]

            # Try to get discovered subdomains from the scan engine context
            scan_id = (config or {}).get("scan_id")
            if scan_id:
                try:
                    from sqlalchemy import select
                    from app.database import ScanResult, AsyncSessionLocal
                    
                    if AsyncSessionLocal is None:
                        from app.database import init_db
                        await init_db()
                        
                    async with AsyncSessionLocal() as db:
                        stmt = select(ScanResult).filter(
                            ScanResult.scan_id == scan_id,
                            ScanResult.result_type == "subdomain",
                        ).limit(15)
                        subdomain_results = (await db.execute(stmt)).scalars().all()
                        
                        for sr in subdomain_results:
                            if sr.value and sr.value != target and sr.value not in hosts_to_scan:
                                hosts_to_scan.append(sr.value)
                except Exception:
                    pass  # If DB access fails, just scan the main target

            data = await fingerprinter.run(
                hostnames=hosts_to_scan,
                analyze_content=True,
            )

            techs = data.get("technologies", {})
            wafs = data.get("wafs", {})
            responses = data.get("responses", {})

            values = []
            parent_values = []
            per_value_metadata = []

            for host, tech_list in techs.items():
                for tech in tech_list:
                    td = tech.to_dict()
                    label = td["name"]
                    if td.get("version"):
                        label += f" {td['version']}"

                    values.append(label)
                    parent_values.append(host)
                    
                    # Attach specific metadata for this tech result
                    per_value_metadata.append({
                        "host": host,
                        "name": td["name"],
                        "version": td.get("version"),
                        "source": td.get("source"),
                        "confidence": td.get("confidence"),
                        "cve_count": len(td.get("cves", [])),
                        "cves": td.get("cves", []),
                        "status_code": responses.get(host, {}).get("status_code"),
                    })

                    # Add CVEs as separate nodes linked to this tech
                    for cve in td.get("cves", []):
                        cve_id = cve.get("cve_id")
                        values.append(cve_id)
                        parent_values.append(label) # Link CVE to the technology
                        per_value_metadata.append({
                            "type": "vulnerability",
                            "host": host,
                            "technology": label,
                            "severity": cve.get("severity"),
                            "cvss_score": cve.get("cvss_score"),
                            "description": cve.get("description"),
                        })

            for host, waf_name in wafs.items():
                if waf_name:
                    values.append(waf_name)
                    parent_values.append(host)
                    per_value_metadata.append({
                        "host": host,
                        "waf_name": waf_name,
                        "type": "waf"
                    })

            result.values = values
            result.parent_values = parent_values
            result.per_value_metadata = per_value_metadata
            result.metadata = {
                "hosts_scanned": len(hosts_to_scan),
                "total_results": len(values),
            }
        except Exception as e:
            result.errors.append(str(e))
            result.success = False
        return result

