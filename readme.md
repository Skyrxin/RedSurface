~# RedSurface v2.0 — Web Edition 🔴

**Attack Surface Intelligence Platform**

RedSurface is a modular, high-performance external reconnaissance web application. It discovers assets, fingerprints technologies, maps vulnerabilities, and generates a stunning interactive **Attack Surface Graph** directly in your browser.

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.109+-teal.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

---

## Features

### 31 Atomic Plugins
RedSurface features a highly modular, async plugin engine boasting **31 independently selectable plugins** across four categories:
*   **Discovery (10):** Subdomain enumeration via crt.sh, RapidDNS, HackerTarget, Shodan InternetDB, SSL Certificate analysis, and more.
*   **OSINT (10):** Email and employee discovery via PGP keyservers, GitHub commits, Hunter.io, Archive.org, and Phonebook.cz.
*   **Threat Intelligence (6):** Reputation and breach checks via AlienVault OTX, URLScan.io, abuse.ch, ThreatCrowd, VirusTotal, and HIBP.
*   **Internal (5):** 
    *   **IP Resolver & Cloud Detector:** Identifies IPv4/IPv6, extracts CNAMEs, and detects cloud hosts (AWS, Azure, GCP, Cloudflare, Fastly, etc.).
    *   **Technology Fingerprinter:** Wappalyzer-style detection across subdomains, identifying WAFs and mapping technologies to **NVD CVEs** with CVSS scores.
    *   **Active Recon:** Directory enumeration, DNS brute-forcing, and Zone Transfers.

### Interactive Attack Surface Graph
Visualize your target's footprint with a beautiful, force-directed **D3.js graph**. Watch in real-time as the domain node expands into subdomains, IP addresses, technologies, open ports, and discovered emails.

### Ultra-Fast Async Engine
Built on **FastAPI** and `httpx`, the scanning engine executes dozens of concurrent reconnaissance tasks without breaking a sweat.

---

## Installation

RedSurface runs natively across Windows, Linux, and macOS.

```bash
git clone https://github.com/Skyrxin/redsurface.git
cd redsurface

# Install dependencies
pip install -r requirements.txt
```

## Usage

Launch the RedSurface web interface:

```bash
python main.py
```

*   **Web Interface:** Open `http://127.0.0.1:5000` in your browser.
*   **API Documentation:** Interactive Swagger UI available at `http://127.0.0.1:5000/docs`.

### Working with Scans
1.  Navigate to **New Scan** in the sidebar.
2.  Enter your target domain (e.g., `example.com`).
3.  Select which of the 31 plugins you wish to run.
4.  Watch the **interactive graph** build itself in real-time as results stream in!

---

## Configure API Keys (Optional)

Many plugins (like crt.sh, RapidDNS, HackerTarget) are **100% free and require no API keys**. 

To unlock the full power of the Threat Intel and enriched OSINT plugins, add your API keys in the **Settings** page of the web UI:
*   **Shodan** (Port/service intelligence)
*   **Hunter.io** (Email discovery)
*   **NVD** (CVE vulnerability mapping limits)
*   **GitHub** (Code/commit OSINT)
*   **HaveIBeenPwned** (Breach detection)
*   **SecurityTrails** (Premium subdomain enumeration)
*   **Censys** (Asset discovery)
*   **AbuseIPDB** (Threat intelligence)
*   **VirusTotal** (Reputation intelligence)

---

## Project Architecture

```text
redsurface/
├── main.py                 # FastAPI Web Server Launcher
├── app/                    # Web Application Core
│   ├── api/                # Async REST Endpoints
│   ├── static/             # CSS (Glassmorphism) & D3.js Graph
│   ├── templates/          # Jinja2 HTML Views
│   ├── database.py         # SQLite Storage Engine
│   └── scan_engine.py      # Async Plugin Orchestration
├── plugins/                # 31 Atomic Plugin Wrappers
│   ├── discovery/          
│   ├── osint/              
│   ├── threat_intel/       
│   └── internal/           
├── modules/                # Core Reconnaissance Engines
│   ├── discovery.py        # Subdomain & DNS resolution
│   ├── fingerprint.py      # Technology & WAF detection
│   └── osint.py            # Email & people discovery
└── data/                   # SQLite Database storage
```

---

## Disclaimer

⚠️ **This tool is intended for authorized security testing and research only.**

- Always obtain proper written authorization before scanning any target.
- Some Active Recon modules (Directory Enum, Zone Transfer) directly interact with the target. Use with caution.
- Unauthorized use may violate computer crime laws.
- The authors are not responsible for misuse of this tool.

## License

MIT
