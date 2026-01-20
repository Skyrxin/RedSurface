#!/usr/bin/env python3
"""
RedSurface HTML Report Generator
Generates professional HTML reports from reconnaissance JSON results.
Includes DataProtect branding and PDF export capability.
"""

import json
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional


# DataProtect logo as base64 (embedded for portability)
DATAPROTECT_LOGO_BASE64 = """
iVBORw0KGgoAAAANSUhEUgAABLAAAACWCAYAAADRJxSMAAAACXBIWXMAAAsTAAALEwEAmpwYAAAF
GmlUWHRYTUw6Y29tLmFkb2JlLnhtcAAAAAAAPD94cGFja2V0IGJlZ2luPSLvu78iIGlkPSJXNU0w
TXBDZWhpSHpyZVN6TlRjemtjOWQiPz4gPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRh
LyIgeDp4bXB0az0iQWRvYmUgWE1QIENvcmUgNy4xLWMwMDAgNzkuZGFiYWNiYiwgMjAyMS8wNC8x
NC0wMDozOTo0NCAgICAgICAgIj4gPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9y
Zy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4gPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9
IiIgeG1sbnM6eG1wPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvIiB4bWxuczpkYz0iaHR0
cDovL3B1cmwub3JnL2RjL2VsZW1lbnRzLzEuMS8iIHhtbG5zOnBob3Rvc2hvcD0iaHR0cDovL25z
LmFkb2JlLmNvbS9waG90b3Nob3AvMS4wLyIgeG1sbnM6eG1wTU09Imh0dHA6Ly9ucy5hZG9iZS5j
b20veGFwLzEuMC9tbS8iIHhtbG5zOnN0RXZ0PSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAv
c1R5cGUvUmVzb3VyY2VFdmVudCMiIHhtcDpDcmVhdG9yVG9vbD0iQWRvYmUgUGhvdG9zaG9wIDIy
LjUgKFdpbmRvd3MpIiB4bXA6Q3JlYXRlRGF0ZT0iMjAyNi0wMS0xOVQyMzowMDowMCswMTowMCIg
eG1wOk1vZGlmeURhdGU9IjIwMjYtMDEtMTlUMjM6MDA6MDArMDE6MDAiIHhtcDpNZXRhZGF0YURh
dGU9IjIwMjYtMDEtMTlUMjM6MDA6MDArMDE6MDAiIGRjOmZvcm1hdD0iaW1hZ2UvcG5nIiBwaG90
b3Nob3A6Q29sb3JNb2RlPSIzIiBwaG90b3Nob3A6SUNDUHJvZmlsZT0ic1JHQiBJRUM2MTk2Ni0y
LjEiIHhtcE1NOkluc3RhbmNlSUQ9InhtcC5paWQ6ZGF0YXByb3RlY3QiIHhtcE1NOkRvY3VtZW50
SUQ9InhtcC5kaWQ6ZGF0YXByb3RlY3QiIHhtcE1NOk9yaWdpbmFsRG9jdW1lbnRJRD0ieG1wLmRp
ZDpkYXRhcHJvdGVjdCI+PC9yZGY6RGVzY3JpcHRpb24+IDwvcmRmOlJERj4gPC94OnhtcG1ldGE+
IDw/eHBhY2tldCBlbmQ9InIiPz7/2wBDAA==
"""


class ReportGenerator:
    """
    Generates professional HTML reports from RedSurface reconnaissance results.
    Compatible with the new enhanced JSON structure.
    """
    
    def __init__(self, results_data: Dict[str, Any], logo_path: Optional[Path] = None):
        """
        Initialize the report generator.
        
        Args:
            results_data: Dictionary containing reconnaissance results
            logo_path: Optional path to custom logo image
        """
        self.results = results_data
        self.logo_path = logo_path
        self.html = []
        
        # Handle both old and new JSON structures
        self.domain = self._get_domain()
        self.meta = self._get_meta()
        self.summary = self._get_summary()
        
    def _get_domain(self) -> str:
        """Extract domain from results (handles both old and new structure)."""
        return self.results.get('domain', 'Unknown')
    
    def _get_meta(self) -> Dict[str, Any]:
        """Extract metadata (handles both old and new structure)."""
        if 'meta' in self.results:
            return self.results['meta']
        # Old structure fallback
        return {
            'scan_start': self.results.get('scan_start'),
            'scan_end': self.results.get('scan_end'),
            'scan_duration_seconds': self.results.get('scan_duration_seconds', 0),
            'scan_config': {}
        }
    
    def _get_summary(self) -> Dict[str, int]:
        """Extract or calculate summary statistics."""
        if 'summary' in self.results:
            return self.results['summary']
        
        # Calculate from old structure
        return {
            'subdomains_count': len(self.results.get('subdomains', [])),
            'ips_count': sum(len(v) for v in self.results.get('ips', {}).values()),
            'technologies_count': sum(len(v) for v in self.results.get('technologies', {}).values()),
            'vulnerabilities_count': sum(len(v) for v in self.results.get('vulnerabilities', {}).values()),
            'emails_count': len(self.results.get('emails', [])),
            'people_count': len(self.results.get('people', [])),
            'directories_count': sum(len(v) for v in self.results.get('discovered_directories', {}).values()),
            'ports_count': 0,
            'cloud_services_count': len(self.results.get('cloud_services', {})),
        }
    
    def _get_subdomains(self) -> List[str]:
        """Get subdomains list."""
        return self.results.get('subdomains', [])
    
    def _get_ips(self) -> Dict[str, List[str]]:
        """Get IP mappings."""
        if 'infrastructure' in self.results:
            return self.results['infrastructure'].get('ip_mappings', {})
        return self.results.get('ips', {})
    
    def _get_technologies(self) -> Dict[str, List[str]]:
        """Get technologies."""
        if 'fingerprinting' in self.results:
            return self.results['fingerprinting'].get('technologies', {})
        return self.results.get('technologies', {})
    
    def _get_technology_details(self) -> Dict[str, List[Dict]]:
        """Get detailed technology info."""
        if 'fingerprinting' in self.results:
            return self.results['fingerprinting'].get('technology_details', {})
        return {}
    
    def _get_vulnerabilities(self) -> Dict[str, List[str]]:
        """Get vulnerabilities."""
        if 'fingerprinting' in self.results:
            return self.results['fingerprinting'].get('vulnerabilities', {})
        return self.results.get('vulnerabilities', {})
    
    def _get_emails(self) -> List[str]:
        """Get emails."""
        if 'osint' in self.results:
            return self.results['osint'].get('emails', [])
        return self.results.get('emails', [])
    
    def _get_people(self) -> List[Dict]:
        """Get people."""
        if 'osint' in self.results:
            return self.results['osint'].get('people', [])
        return self.results.get('people', [])
    
    def _get_cloud_services(self) -> Dict[str, str]:
        """Get cloud services."""
        if 'infrastructure' in self.results:
            return self.results['infrastructure'].get('cloud_services', {})
        return self.results.get('cloud_services', {})
    
    def _get_ssl_certificates(self) -> Dict[str, Dict]:
        """Get SSL certificates."""
        if 'infrastructure' in self.results:
            return self.results['infrastructure'].get('ssl_certificates', {})
        return {}
    
    def _get_dns_records(self) -> Dict[str, Dict]:
        """Get DNS records."""
        if 'infrastructure' in self.results:
            return self.results['infrastructure'].get('dns_records', {})
        return self.results.get('dns_records', {})
    
    def _get_directories(self) -> Dict[str, List[Dict]]:
        """Get discovered directories."""
        if 'active_recon' in self.results:
            return self.results['active_recon'].get('directory_enumeration', {})
        return self.results.get('discovered_directories', {})
    
    def _get_port_intel(self) -> Dict[str, Dict]:
        """Get port intelligence."""
        return self.results.get('port_intelligence', self.results.get('port_intel', {}))
    
    def _get_http_responses(self) -> Dict[str, Dict]:
        """Get HTTP responses."""
        return self.results.get('http_responses', {})
    
    def _get_zone_transfer(self) -> Dict[str, Any]:
        """Get zone transfer results."""
        if 'active_recon' in self.results:
            return self.results['active_recon'].get('zone_transfer', {})
        return {}
    
    def _get_assets(self) -> Dict[str, Dict]:
        """Get infrastructure assets."""
        if 'infrastructure' in self.results:
            return self.results['infrastructure'].get('assets', {})
        return {}
    
    def w(self, text: str) -> None:
        """Write line to HTML output."""
        self.html.append(text)
    
    def generate(self) -> str:
        """Generate complete HTML report."""
        self._add_html_head()
        self._add_header()
        self._add_navigation()
        self._add_executive_summary()
        
        # Add sections based on available data
        if self._get_subdomains():
            self._add_subdomains_section()
        
        if self._get_ips():
            self._add_ips_section()
        
        if self._get_ssl_certificates():
            self._add_ssl_section()
        
        if self._get_technologies():
            self._add_technologies_section()
        
        if self._get_vulnerabilities():
            self._add_vulnerabilities_section()
        
        if self._get_emails():
            self._add_emails_section()
        
        if self._get_people():
            self._add_personnel_section()
        
        if self._get_cloud_services():
            self._add_cloud_section()
        
        if self._get_port_intel():
            self._add_port_intel_section()
        
        if self._get_dns_records():
            self._add_dns_section()
        
        if self._get_directories():
            self._add_directories_section()
        
        if self._get_http_responses():
            self._add_http_responses_section()
        
        if self._get_zone_transfer():
            self._add_zone_transfer_section()
        
        self._add_scan_config_section()
        self._add_footer()
        
        return '\n'.join(self.html)
    
    def _add_html_head(self) -> None:
        """Add HTML head with CSS styles."""
        self.w(f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RedSurface Report - {self.domain}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.10.1/html2pdf.bundle.min.js"></script>
<style>
:root {{
    --primary: #e11d48;
    --primary-dark: #be123c;
    --secondary: #1a1a2e;
    --accent: #ff4757;
    --bg: #fafafa;
    --card-bg: #ffffff;
    --text: #1a1a2e;
    --text-muted: #64748b;
    --border: #e2e8f0;
    --success: #10b981;
    --warning: #f59e0b;
    --danger: #ef4444;
    --info: #3b82f6;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
html {{ scroll-behavior: smooth; }}
body {{
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
    line-height: 1.6;
    color: var(--text);
    background: var(--bg);
}}
.container {{
    max-width: 1400px;
    margin: 0 auto;
    background: var(--card-bg);
    box-shadow: 0 4px 20px rgba(0,0,0,0.08);
}}
.header {{
    background: linear-gradient(135deg, var(--secondary) 0%, #16213e 100%);
    color: white;
    padding: 40px;
    position: relative;
}}
.header-content {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 30px;
}}
.logo-section {{
    display: flex;
    align-items: center;
    gap: 20px;
}}
.logo {{
    height: 60px;
    width: auto;
}}
.logo-text {{
    font-size: 1.8rem;
    font-weight: 700;
}}
.logo-text span {{
    color: var(--primary);
}}
.header-info {{
    text-align: right;
}}
.header h1 {{
    font-size: 2rem;
    font-weight: 600;
    margin-bottom: 5px;
}}
.header .subtitle {{
    color: rgba(255,255,255,0.8);
    font-size: 1rem;
}}
.meta-bar {{
    background: rgba(255,255,255,0.1);
    padding: 15px 40px;
    display: flex;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 20px;
    border-top: 1px solid rgba(255,255,255,0.1);
}}
.meta-item {{
    font-size: 0.9rem;
    color: rgba(255,255,255,0.9);
}}
.meta-item strong {{
    color: var(--primary);
}}
.pdf-btn {{
    position: absolute;
    top: 20px;
    right: 20px;
    background: var(--primary);
    color: white;
    border: none;
    padding: 12px 24px;
    border-radius: 6px;
    cursor: pointer;
    font-weight: 600;
    font-size: 0.9rem;
    transition: all 0.3s;
    display: flex;
    align-items: center;
    gap: 8px;
}}
.pdf-btn:hover {{
    background: var(--primary-dark);
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(225,29,72,0.3);
}}
.nav {{
    background: var(--card-bg);
    border-bottom: 2px solid var(--primary);
    padding: 0;
    position: sticky;
    top: 0;
    z-index: 100;
    box-shadow: 0 2px 10px rgba(0,0,0,0.05);
}}
.nav-inner {{
    max-width: 1400px;
    margin: 0 auto;
    display: flex;
    flex-wrap: wrap;
    overflow-x: auto;
}}
.nav a {{
    color: var(--text);
    padding: 15px 20px;
    text-decoration: none;
    font-weight: 500;
    font-size: 0.85rem;
    border-bottom: 3px solid transparent;
    transition: all 0.2s;
    white-space: nowrap;
}}
.nav a:hover {{
    background: rgba(225,29,72,0.05);
    border-bottom-color: var(--primary);
    color: var(--primary);
}}
.content {{
    padding: 40px;
}}
.section {{
    margin-bottom: 50px;
    scroll-margin-top: 70px;
}}
.section-title {{
    font-size: 1.5rem;
    font-weight: 700;
    color: var(--secondary);
    margin-bottom: 20px;
    padding-bottom: 10px;
    border-bottom: 3px solid var(--primary);
    display: flex;
    align-items: center;
    gap: 10px;
}}
.section-title .icon {{
    font-size: 1.3rem;
}}
.stat-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 20px;
    margin: 30px 0;
}}
.stat-card {{
    background: linear-gradient(135deg, #fff 0%, #fef2f2 100%);
    border-left: 4px solid var(--primary);
    padding: 25px 20px;
    border-radius: 8px;
    transition: all 0.3s;
}}
.stat-card:hover {{
    transform: translateY(-3px);
    box-shadow: 0 8px 20px rgba(225,29,72,0.1);
}}
.stat-num {{
    font-size: 2.5rem;
    font-weight: 700;
    color: var(--primary);
    line-height: 1;
}}
.stat-label {{
    font-size: 0.85rem;
    color: var(--text-muted);
    margin-top: 8px;
    font-weight: 500;
}}
.card {{
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
    margin: 15px 0;
}}
.card-title {{
    font-size: 1.1rem;
    font-weight: 600;
    color: var(--secondary);
    margin-bottom: 15px;
    padding-bottom: 10px;
    border-bottom: 1px solid var(--border);
}}
.list {{
    list-style: none;
}}
.list li {{
    padding: 12px 15px;
    margin: 6px 0;
    background: var(--bg);
    border-left: 3px solid var(--border);
    border-radius: 4px;
    font-family: 'Consolas', monospace;
    font-size: 0.9rem;
    transition: all 0.2s;
}}
.list li:hover {{
    background: #fef2f2;
    border-left-color: var(--primary);
}}
.badge {{
    display: inline-block;
    padding: 4px 12px;
    border-radius: 20px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
}}
.badge-critical {{ background: #fecaca; color: #991b1b; }}
.badge-high {{ background: #fed7aa; color: #9a3412; }}
.badge-medium {{ background: #fef08a; color: #854d0e; }}
.badge-low {{ background: #bbf7d0; color: #166534; }}
.badge-info {{ background: #dbeafe; color: #1e40af; }}
.badge-success {{ background: #d1fae5; color: #065f46; }}
.table {{
    width: 100%;
    border-collapse: collapse;
    margin: 15px 0;
    font-size: 0.9rem;
}}
.table th {{
    background: var(--secondary);
    color: white;
    padding: 12px 15px;
    text-align: left;
    font-weight: 600;
}}
.table td {{
    padding: 12px 15px;
    border-bottom: 1px solid var(--border);
}}
.table tr:hover {{
    background: rgba(225,29,72,0.03);
}}
.table td:first-child {{
    font-family: 'Consolas', monospace;
    color: var(--primary);
    font-weight: 500;
}}
.tech-grid {{
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    margin: 10px 0;
}}
.tech-badge {{
    background: #fef2f2;
    color: var(--primary);
    border: 1px solid #fecaca;
    padding: 8px 16px;
    border-radius: 20px;
    font-size: 0.85rem;
    font-weight: 500;
    transition: all 0.2s;
}}
.tech-badge:hover {{
    background: var(--primary);
    color: white;
}}
.vuln-card {{
    background: #fef2f2;
    border-left: 4px solid var(--danger);
    padding: 15px 20px;
    margin: 10px 0;
    border-radius: 6px;
}}
.vuln-card h4 {{
    color: var(--danger);
    margin-bottom: 8px;
}}
.vuln-card a {{
    color: var(--danger);
    text-decoration: none;
    font-weight: 600;
}}
.vuln-card a:hover {{
    text-decoration: underline;
}}
.person-card {{
    background: var(--bg);
    border-radius: 8px;
    padding: 15px 20px;
    margin: 10px 0;
    border-left: 4px solid var(--primary);
}}
.person-name {{
    font-weight: 600;
    color: var(--secondary);
    font-size: 1rem;
}}
.person-detail {{
    font-size: 0.85rem;
    color: var(--text-muted);
    margin-top: 5px;
    font-family: 'Consolas', monospace;
}}
.ssl-card {{
    background: linear-gradient(135deg, #ecfdf5 0%, #d1fae5 100%);
    border-left: 4px solid var(--success);
    padding: 20px;
    margin: 10px 0;
    border-radius: 8px;
}}
.ssl-card.expired {{
    background: linear-gradient(135deg, #fef2f2 0%, #fecaca 100%);
    border-left-color: var(--danger);
}}
.ssl-card h4 {{
    color: var(--secondary);
    margin-bottom: 10px;
}}
.ssl-detail {{
    font-size: 0.85rem;
    color: var(--text-muted);
    margin: 5px 0;
}}
.port-card {{
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
    margin: 15px 0;
}}
.port-header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 15px;
    padding-bottom: 10px;
    border-bottom: 1px solid var(--border);
}}
.port-ip {{
    font-family: 'Consolas', monospace;
    font-size: 1.1rem;
    font-weight: 600;
    color: var(--primary);
}}
.port-list {{
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
}}
.port-badge {{
    background: var(--secondary);
    color: white;
    padding: 6px 12px;
    border-radius: 4px;
    font-family: 'Consolas', monospace;
    font-size: 0.85rem;
}}
.info-box {{
    background: #fef2f2;
    border: 1px solid #fecaca;
    padding: 20px;
    border-radius: 8px;
    margin: 15px 0;
}}
.info-box-title {{
    font-weight: 600;
    color: var(--primary);
    margin-bottom: 10px;
}}
.footer {{
    background: var(--secondary);
    color: white;
    padding: 30px 40px;
    text-align: center;
}}
.footer-logo {{
    margin-bottom: 15px;
}}
.footer-logo img {{
    height: 40px;
}}
.footer p {{
    opacity: 0.8;
    font-size: 0.9rem;
}}
.back-to-top {{
    position: fixed;
    bottom: 30px;
    right: 30px;
    background: var(--primary);
    color: white;
    width: 50px;
    height: 50px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    font-size: 1.5rem;
    box-shadow: 0 4px 15px rgba(225,29,72,0.3);
    transition: all 0.3s;
    opacity: 0;
    pointer-events: none;
}}
.back-to-top.visible {{
    opacity: 1;
    pointer-events: auto;
}}
.back-to-top:hover {{
    transform: translateY(-5px);
}}
@media print {{
    .pdf-btn, .nav, .back-to-top {{ display: none; }}
    .header {{ padding: 30px; }}
    .content {{ padding: 20px; }}
}}
@media (max-width: 768px) {{
    .header-content {{ flex-direction: column; text-align: center; }}
    .header-info {{ text-align: center; }}
    .meta-bar {{ justify-content: center; }}
    .nav-inner {{ flex-direction: column; }}
    .nav a {{ border-left: 3px solid transparent; border-bottom: none; }}
    .nav a:hover {{ border-left-color: var(--primary); }}
}}
</style>
</head>
<body>
<div class="container" id="report">''')

    def _add_header(self) -> None:
        """Add report header with logo."""
        scan_start = self.meta.get('scan_start', 'N/A')
        if scan_start and scan_start != 'N/A':
            scan_start = scan_start[:19].replace('T', ' ')
        
        duration = self.meta.get('scan_duration_seconds', 0) or 0
        mode = self.meta.get('scan_config', {}).get('mode', 'passive').upper()
        
        self.w(f'''
<div class="header">
    <button class="pdf-btn" onclick="downloadPDF()">📄 Export PDF</button>
    <div class="header-content">
        <div class="logo-section">
            <div class="logo-text"><span>DATA</span>PROTECT</div>
        </div>
        <div class="header-info">
            <h1>Reconnaissance Report</h1>
            <div class="subtitle">External Attack Surface Assessment</div>
        </div>
    </div>
</div>
<div class="meta-bar">
    <div class="meta-item"><strong>Target:</strong> {self.domain}</div>
    <div class="meta-item"><strong>Scan Date:</strong> {scan_start}</div>
    <div class="meta-item"><strong>Duration:</strong> {duration:.2f}s</div>
    <div class="meta-item"><strong>Mode:</strong> {mode}</div>
</div>''')

    def _add_navigation(self) -> None:
        """Add navigation bar."""
        self.w('<nav class="nav"><div class="nav-inner">')
        self.w('<a href="#summary">📊 Summary</a>')
        
        if self._get_subdomains():
            self.w('<a href="#subdomains">🌐 Subdomains</a>')
        if self._get_ips():
            self.w('<a href="#ips">🖥️ IPs</a>')
        if self._get_ssl_certificates():
            self.w('<a href="#ssl">🔒 SSL</a>')
        if self._get_technologies():
            self.w('<a href="#technologies">⚙️ Technologies</a>')
        if self._get_vulnerabilities():
            self.w('<a href="#vulnerabilities">🔴 CVEs</a>')
        if self._get_emails():
            self.w('<a href="#emails">📧 Emails</a>')
        if self._get_people():
            self.w('<a href="#personnel">👤 Personnel</a>')
        if self._get_cloud_services():
            self.w('<a href="#cloud">☁️ Cloud</a>')
        if self._get_port_intel():
            self.w('<a href="#ports">🔌 Ports</a>')
        if self._get_dns_records():
            self.w('<a href="#dns">📋 DNS</a>')
        if self._get_directories():
            self.w('<a href="#directories">📁 Directories</a>')
        if self._get_http_responses():
            self.w('<a href="#http">🌍 HTTP</a>')
        
        self.w('<a href="#config">⚙️ Config</a>')
        self.w('</div></nav><div class="content">')

    def _add_executive_summary(self) -> None:
        """Add executive summary with statistics."""
        s = self.summary
        
        self.w('''
<section class="section" id="summary">
<h2 class="section-title"><span class="icon">📊</span> Executive Summary</h2>
<div class="stat-grid">''')
        
        stats = [
            (s.get('subdomains_count', 0), 'Subdomains', '🌐'),
            (s.get('ips_count', 0), 'IP Addresses', '🖥️'),
            (s.get('technologies_count', 0), 'Technologies', '⚙️'),
            (s.get('vulnerabilities_count', 0), 'CVEs Found', '🔴'),
            (s.get('emails_count', 0), 'Emails', '📧'),
            (s.get('people_count', 0), 'Personnel', '👤'),
            (s.get('cloud_services_count', 0), 'Cloud Services', '☁️'),
            (s.get('directories_count', 0), 'Directories', '📁'),
            (s.get('ports_count', 0), 'Open Ports', '🔌'),
        ]
        
        for count, label, icon in stats:
            if count > 0:
                self.w(f'''
<div class="stat-card">
    <div class="stat-num">{count}</div>
    <div class="stat-label">{icon} {label}</div>
</div>''')
        
        self.w('</div></section>')

    def _add_subdomains_section(self) -> None:
        """Add subdomains section."""
        subs = self._get_subdomains()
        self.w(f'''
<section class="section" id="subdomains">
<h2 class="section-title"><span class="icon">🌐</span> Subdomains ({len(subs)})</h2>
<ul class="list">''')
        for sub in sorted(subs):
            self.w(f'<li>{sub}</li>')
        self.w('</ul></section>')

    def _add_ips_section(self) -> None:
        """Add IP addresses section."""
        ips = self._get_ips()
        total = sum(len(v) for v in ips.values())
        
        self.w(f'''
<section class="section" id="ips">
<h2 class="section-title"><span class="icon">🖥️</span> IP Addresses ({total})</h2>
<table class="table">
<thead><tr><th>Hostname</th><th>IP Address</th></tr></thead>
<tbody>''')
        
        for host, ip_list in sorted(ips.items()):
            for ip in ip_list:
                self.w(f'<tr><td>{host}</td><td>{ip}</td></tr>')
        
        self.w('</tbody></table></section>')

    def _add_ssl_section(self) -> None:
        """Add SSL certificates section."""
        certs = self._get_ssl_certificates()
        
        self.w(f'''
<section class="section" id="ssl">
<h2 class="section-title"><span class="icon">🔒</span> SSL/TLS Certificates ({len(certs)})</h2>''')
        
        for host, cert in certs.items():
            is_expired = cert.get('is_expired', False)
            card_class = 'ssl-card expired' if is_expired else 'ssl-card'
            
            self.w(f'''
<div class="{card_class}">
    <h4>{host}</h4>
    <div class="ssl-detail"><strong>Subject:</strong> {cert.get('subject', 'N/A')}</div>
    <div class="ssl-detail"><strong>Issuer:</strong> {cert.get('issuer', 'N/A')}</div>
    <div class="ssl-detail"><strong>Valid Until:</strong> {cert.get('not_after', 'N/A')}</div>
    <div class="ssl-detail"><strong>Days Until Expiry:</strong> {cert.get('days_until_expiry', 'N/A')}</div>
    <div class="ssl-detail"><strong>SAN Domains:</strong> {', '.join(cert.get('san_domains', []))}</div>
    {f'<span class="badge badge-critical">EXPIRED</span>' if is_expired else '<span class="badge badge-success">VALID</span>'}
    {f'<span class="badge badge-medium">SELF-SIGNED</span>' if cert.get('is_self_signed') else ''}
</div>''')
        
        self.w('</section>')

    def _add_technologies_section(self) -> None:
        """Add technologies section with details."""
        techs = self._get_technologies()
        tech_details = self._get_technology_details()
        
        self.w('''
<section class="section" id="technologies">
<h2 class="section-title"><span class="icon">⚙️</span> Technologies</h2>''')
        
        for host, tech_list in techs.items():
            self.w(f'<div class="card"><div class="card-title">{host}</div>')
            self.w('<div class="tech-grid">')
            for tech in tech_list:
                self.w(f'<span class="tech-badge">{tech}</span>')
            self.w('</div>')
            
            # Add detailed CVE info if available
            if host in tech_details:
                for detail in tech_details[host]:
                    if detail.get('cves'):
                        self.w(f'<div style="margin-top:15px;padding-top:15px;border-top:1px solid var(--border)">')
                        self.w(f'<strong>{detail.get("full_name", detail.get("name"))}:</strong>')
                        for cve in detail['cves'][:3]:  # Limit to 3 CVEs per tech
                            cve_id = cve.get('cve_id', 'Unknown')
                            severity = cve.get('severity', 'Unknown')
                            self.w(f'<div style="margin:5px 0;font-size:0.85rem;color:var(--text-muted)">')
                            self.w(f'<a href="https://nvd.nist.gov/vuln/detail/{cve_id}" target="_blank" style="color:var(--danger)">{cve_id}</a>')
                            self.w(f' - {severity} (CVSS: {cve.get("cvss_score", "N/A")})</div>')
                        self.w('</div>')
            
            self.w('</div>')
        
        self.w('</section>')

    def _add_vulnerabilities_section(self) -> None:
        """Add vulnerabilities section."""
        vulns = self._get_vulnerabilities()
        total = sum(len(v) for v in vulns.values())
        
        self.w(f'''
<section class="section" id="vulnerabilities">
<h2 class="section-title"><span class="icon">🔴</span> Potential Vulnerabilities ({total})</h2>''')
        
        for tech, cves in vulns.items():
            self.w(f'<div class="card"><div class="card-title">{tech} ({len(cves)} CVEs)</div>')
            for cve in cves:
                year = cve.split('-')[1] if '-' in cve else 'Unknown'
                self.w(f'''
<div class="vuln-card">
    <h4><a href="https://nvd.nist.gov/vuln/detail/{cve}" target="_blank">{cve}</a></h4>
    <span class="badge badge-high">CVE</span>
    <span style="color:var(--text-muted);font-size:0.85rem">Year: {year}</span>
</div>''')
            self.w('</div>')
        
        self.w('</section>')

    def _add_emails_section(self) -> None:
        """Add emails section."""
        emails = self._get_emails()
        
        self.w(f'''
<section class="section" id="emails">
<h2 class="section-title"><span class="icon">📧</span> Email Addresses ({len(emails)})</h2>
<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:10px">''')
        
        for email in emails:
            self.w(f'<div class="list"><li>{email}</li></div>')
        
        self.w('</div></section>')

    def _add_personnel_section(self) -> None:
        """Add personnel section."""
        people = self._get_people()
        
        self.w(f'''
<section class="section" id="personnel">
<h2 class="section-title"><span class="icon">👤</span> Personnel ({len(people)})</h2>''')
        
        for person in people:
            name = person.get('name', 'Unknown')
            email = person.get('email', 'N/A')
            role = person.get('role', 'Unknown')
            source = person.get('source', 'Unknown')
            
            self.w(f'''
<div class="person-card">
    <div class="person-name">{name}</div>
    <div class="person-detail">📧 {email}</div>
    <div class="person-detail">💼 {role}</div>
    <div class="person-detail">📍 Source: {source}</div>
</div>''')
        
        self.w('</section>')

    def _add_cloud_section(self) -> None:
        """Add cloud services section."""
        cloud = self._get_cloud_services()
        
        self.w('''
<section class="section" id="cloud">
<h2 class="section-title"><span class="icon">☁️</span> Cloud Services</h2>
<table class="table">
<thead><tr><th>IP Address</th><th>Cloud Provider</th></tr></thead>
<tbody>''')
        
        for ip, provider in cloud.items():
            self.w(f'<tr><td>{ip}</td><td><span class="badge badge-info">{provider}</span></td></tr>')
        
        self.w('</tbody></table></section>')

    def _add_port_intel_section(self) -> None:
        """Add port intelligence section."""
        port_intel = self._get_port_intel()
        
        self.w('''
<section class="section" id="ports">
<h2 class="section-title"><span class="icon">🔌</span> Port Intelligence (Shodan)</h2>''')
        
        for ip, intel in port_intel.items():
            ports = intel.get('ports', [])
            services = intel.get('services', [])
            org = intel.get('org', 'Unknown')
            country = intel.get('country', 'Unknown')
            vulns = intel.get('vulns', [])
            
            self.w(f'''
<div class="port-card">
    <div class="port-header">
        <div class="port-ip">{ip}</div>
        <div><span class="badge badge-info">{org}</span> <span class="badge badge-low">{country}</span></div>
    </div>
    <div style="margin-bottom:10px"><strong>Ports:</strong></div>
    <div class="port-list">''')
            
            for port in ports:
                self.w(f'<span class="port-badge">{port}</span>')
            
            self.w('</div>')
            
            if services:
                self.w('<div style="margin-top:15px"><strong>Services:</strong></div>')
                for svc in services[:5]:  # Limit to 5 services
                    port = svc.get('port', 'N/A')
                    product = svc.get('product', 'Unknown')
                    self.w(f'<div style="font-size:0.85rem;color:var(--text-muted);margin:5px 0">Port {port}: {product}</div>')
            
            if vulns:
                self.w(f'<div style="margin-top:15px"><strong style="color:var(--danger)">Vulnerabilities ({len(vulns)}):</strong></div>')
                for vuln in vulns[:5]:
                    self.w(f'<span class="badge badge-critical" style="margin:2px">{vuln}</span>')
            
            self.w('</div>')
        
        self.w('</section>')

    def _add_dns_section(self) -> None:
        """Add DNS records section."""
        dns = self._get_dns_records()
        
        self.w('''
<section class="section" id="dns">
<h2 class="section-title"><span class="icon">📋</span> DNS Records</h2>''')
        
        for host, records in dns.items():
            self.w(f'<div class="card"><div class="card-title">{host}</div>')
            for record_type, values in records.items():
                self.w(f'<div style="margin:10px 0"><strong>{record_type}:</strong></div><ul class="list">')
                for val in values:
                    self.w(f'<li>{val}</li>')
                self.w('</ul>')
            self.w('</div>')
        
        self.w('</section>')

    def _add_directories_section(self) -> None:
        """Add discovered directories section."""
        dirs = self._get_directories()
        total = sum(len(v) for v in dirs.values())
        
        self.w(f'''
<section class="section" id="directories">
<h2 class="section-title"><span class="icon">📁</span> Discovered Directories ({total})</h2>''')
        
        for host, dir_list in dirs.items():
            self.w(f'''
<div class="card">
<div class="card-title">{host} ({len(dir_list)} paths)</div>
<table class="table">
<thead><tr><th>Path</th><th>Status</th><th>Size</th><th>Type</th></tr></thead>
<tbody>''')
            
            for d in dir_list:
                path = d.get('path', 'N/A')
                status = d.get('status_code', 'N/A')
                size = d.get('content_length', 0)
                ctype = d.get('content_type', 'N/A')[:30]
                
                # Status badge
                if status == 200:
                    badge = '<span class="badge badge-success">200</span>'
                elif status in [301, 302]:
                    badge = '<span class="badge badge-info">{}</span>'.format(status)
                elif status == 403:
                    badge = '<span class="badge badge-medium">403</span>'
                else:
                    badge = '<span class="badge badge-low">{}</span>'.format(status)
                
                size_str = f'{size/1024:.1f}KB' if size > 1024 else f'{size}B'
                
                self.w(f'<tr><td>/{path}</td><td>{badge}</td><td>{size_str}</td><td>{ctype}</td></tr>')
            
            self.w('</tbody></table></div>')
        
        self.w('</section>')

    def _add_http_responses_section(self) -> None:
        """Add HTTP responses section."""
        responses = self._get_http_responses()
        
        self.w(f'''
<section class="section" id="http">
<h2 class="section-title"><span class="icon">🌍</span> HTTP Responses ({len(responses)})</h2>''')
        
        for host, resp in responses.items():
            server = resp.get('server', 'Unknown')
            ctype = resp.get('content_type', 'Unknown')
            
            self.w(f'''
<div class="card">
    <div class="card-title">{host}</div>
    <div style="font-size:0.9rem;color:var(--text-muted)">
        <div><strong>Server:</strong> {server}</div>
        <div><strong>Content-Type:</strong> {ctype}</div>
    </div>
</div>''')
        
        self.w('</section>')

    def _add_zone_transfer_section(self) -> None:
        """Add zone transfer results section."""
        zt = self._get_zone_transfer()
        if not zt:
            return
        
        success = zt.get('success', False)
        ns = zt.get('nameserver', 'N/A')
        subs = zt.get('subdomains', [])
        
        self.w(f'''
<section class="section" id="zone-transfer">
<h2 class="section-title"><span class="icon">🔓</span> Zone Transfer</h2>
<div class="info-box">
    <div><strong>Status:</strong> {'<span class="badge badge-critical">VULNERABLE</span>' if success else '<span class="badge badge-success">Protected</span>'}</div>
    <div><strong>Nameserver:</strong> {ns}</div>
</div>''')
        
        if subs:
            self.w(f'<div class="card"><div class="card-title">Leaked Subdomains ({len(subs)})</div><ul class="list">')
            for sub in subs:
                self.w(f'<li>{sub}</li>')
            self.w('</ul></div>')
        
        self.w('</section>')

    def _add_scan_config_section(self) -> None:
        """Add scan configuration section."""
        config = self.meta.get('scan_config', {})
        
        self.w('''
<section class="section" id="config">
<h2 class="section-title"><span class="icon">⚙️</span> Scan Configuration</h2>
<div class="card">
<table class="table">
<thead><tr><th>Setting</th><th>Value</th></tr></thead>
<tbody>''')
        
        display_config = {
            'Mode': config.get('mode', 'passive'),
            'DNS Timeout': f"{config.get('dns_timeout', 3.0)}s",
            'HTTP Timeout': f"{config.get('http_timeout', 10.0)}s",
            'Max Concurrent': config.get('max_concurrent', 50),
            'System DNS': '✓' if config.get('use_system_dns') else '✗',
            'Shodan API': '✓' if config.get('has_shodan_key') else '✗',
            'NVD API': '✓' if config.get('has_nvd_key') else '✗',
            'Hunter API': '✓' if config.get('has_hunter_key') else '✗',
        }
        
        for key, value in display_config.items():
            self.w(f'<tr><td>{key}</td><td>{value}</td></tr>')
        
        # Add enabled modules for custom mode
        if 'modules_enabled' in config:
            self.w('<tr><td colspan="2" style="background:var(--bg);font-weight:600">Enabled Modules</td></tr>')
            for module, enabled in config['modules_enabled'].items():
                status = '<span class="badge badge-success">ON</span>' if enabled else '<span class="badge badge-low">OFF</span>'
                self.w(f'<tr><td>{module.replace("_", " ").title()}</td><td>{status}</td></tr>')
        
        self.w('</tbody></table></div></section>')

    def _add_footer(self) -> None:
        """Add report footer."""
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        self.w(f'''</div>
<div class="footer">
    <div class="footer-logo">
        <div style="font-size:1.5rem;font-weight:700"><span style="color:var(--primary)">DATA</span>PROTECT</div>
        <div style="font-size:0.8rem;opacity:0.7">Security is our commitment</div>
    </div>
    <p><strong>End of Report</strong></p>
    <p style="margin-top:10px;opacity:0.6">Generated by RedSurface | {now}</p>
</div>
</div>
<div class="back-to-top" onclick="window.scrollTo({{top:0,behavior:'smooth'}})">↑</div>
<script>
function downloadPDF() {{
    const element = document.getElementById('report');
    const opt = {{
        margin: [10, 10, 10, 10],
        filename: '{self.domain}_recon_report.pdf',
        image: {{ type: 'jpeg', quality: 0.98 }},
        html2canvas: {{ scale: 2, useCORS: true, logging: false }},
        jsPDF: {{ unit: 'mm', format: 'a4', orientation: 'portrait' }},
        pagebreak: {{ mode: ['avoid-all', 'css', 'legacy'] }}
    }};
    
    // Show loading
    const btn = document.querySelector('.pdf-btn');
    const originalText = btn.innerHTML;
    btn.innerHTML = '⏳ Generating...';
    btn.disabled = true;
    
    html2pdf().set(opt).from(element).save().then(function() {{
        btn.innerHTML = originalText;
        btn.disabled = false;
    }});
}}

window.addEventListener('scroll', function() {{
    const btn = document.querySelector('.back-to-top');
    if (window.scrollY > 300) {{
        btn.classList.add('visible');
    }} else {{
        btn.classList.remove('visible');
    }}
}});
</script>
</body>
</html>''')


def generate_report(results_file: str, output_file: str = None) -> str:
    """
    Generate HTML report from results JSON file.
    
    Args:
        results_file: Path to the results JSON file
        output_file: Optional output file path (auto-generated if not provided)
    
    Returns:
        Path to the generated report
    """
    results_path = Path(results_file)
    
    with open(results_path, 'r', encoding='utf-8') as f:
        results_data = json.load(f)
    
    generator = ReportGenerator(results_data)
    html = generator.generate()
    
    if output_file is None:
        output_file = results_path.parent / f"{results_path.stem}_report.html"
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html)
    
    return str(output_file)


def main():
    """CLI entry point for standalone usage."""
    parser = argparse.ArgumentParser(
        description='Generate HTML report from RedSurface reconnaissance results'
    )
    parser.add_argument('results_file', help='Path to *_results.json file')
    parser.add_argument('-o', '--output', help='Output HTML file path')
    args = parser.parse_args()
    
    print(f"[*] Generating HTML report from {args.results_file}...")
    
    output_path = generate_report(args.results_file, args.output)
    
    print(f"[+] Report generated: {output_path}")
    print(f"[+] Open in browser to view and export as PDF")


if __name__ == "__main__":
    main()
