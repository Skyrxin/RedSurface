# RedSurface

**Attack Surface Intelligence Graph Generator**

A modular Python CLI tool for external reconnaissance that discovers assets, fingerprints technologies, maps vulnerabilities, and generates an interactive Attack Surface Graph with comprehensive HTML reports.

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

## Features

### 🔍 Reconnaissance
- **Infrastructure Discovery** - Subdomain enumeration via crt.sh, CertSpotter, HackerTarget
- **Async DNS Resolution** - Fast A/AAAA record resolution with system DNS support
- **SSL Certificate Analysis** - Certificate chain inspection and validation
- **Cloud Detection** - Identifies AWS, Azure, GCP, Cloudflare hosted assets

### 🔬 Fingerprinting
- **Technology Detection** - Wappalyzer-style detection from HTTP headers & content
- **WAF Detection** - Identifies web application firewalls
- **Vulnerability Mapping** - Maps technologies to known CVEs via NVD

### 📡 OSINT Collection
- **Email Discovery** - PGP keyservers, GitHub commits, Hunter.io, crt.sh
- **People Discovery** - Employee identification and correlation
- **Breach Detection** - HaveIBeenPwned integration

### ⚡ Active Reconnaissance
- **Directory Enumeration** - Async directory/file bruteforcing
- **Zone Transfer** - DNS AXFR attempts
- **Port Intelligence** - Shodan API integration for service discovery

### 🎣 Phishing Simulation
- **Email Campaign** - Pre-built phishing email templates
- **Landing Pages** - Credential capture pages (Microsoft, Google, Generic)
- **Click Tracking** - Real-time campaign monitoring with Flask server
- **OSINT Integration** - Auto-target discovered emails

### 📊 Output & Visualization
- **Interactive Graph** - HTML visualization with vis.js
- **HTML Reports** - Professional reconnaissance reports
- **JSON Export** - Machine-readable results

## Installation

```bash
git clone https://github.com/Skyrxin/redsurface.git
cd redsurface
pip install -r requirements.txt
```

## Quick Start

### Interactive Mode (Recommended)
```bash
python main.py --interactive
```

The interactive wizard guides you through:
1. **Scan Mode** - Passive, Active, Phishing, or Custom
2. **Target Selection** - Single domain, multiple, or file input
3. **Module Selection** - Choose specific modules (Custom mode)
4. **API Keys** - Configure Shodan, Hunter.io, NVD, GitHub, HIBP
5. **Output Options** - Directory, verbosity, DNS settings

### Command Line

```bash
# Basic passive scan
python main.py --target example.com

# Active scan with directory enumeration
python main.py --target example.com --mode active

# With API keys for enhanced OSINT
python main.py --target example.com --hunter-key YOUR_KEY --github-token YOUR_TOKEN

# Bulk scan from file
python main.py --input-file domains.txt --mode passive

# Phishing simulation (requires SMTP config)
python main.py --target example.com --phishing --smtp-host smtp.example.com --smtp-user user --smtp-pass pass

# Skip OSINT phase
python main.py --target example.com --skip-osint

# Use system DNS resolver
python main.py --target example.com --use-system-dns
```

## Scan Modes

| Mode | Description |
|------|-------------|
| **Passive** | OSINT + DNS only (no direct target interaction) |
| **Active** | Full scan with directory enumeration + zone transfer |
| **Phishing** | Passive recon + phishing campaign simulation |
| **Custom** | Select specific modules to run |

## Output

Results are saved to `./output/` (configurable):

| File | Description |
|------|-------------|
| `domain_results.json` | Raw scan data |
| `domain_graph.json` | Graph structure |
| `domain_graph.html` | Interactive visualization |
| `domain_report.html` | Professional HTML report |
| `redsurface.log` | Detailed scan log |

## Graph Node Types

| Node | Shape | Color | Description |
|------|-------|-------|-------------|
| Domain | Diamond | Indigo | Root target domain |
| Subdomain | Dot | Purple | Discovered subdomains |
| IP | Dot | Green/Orange | Resolved IPs (orange = cloud) |
| Technology | Box | Blue | Detected technologies |
| Vulnerability | Triangle | Red | Mapped CVEs |
| Email | Box | Gold | Discovered emails |
| Person | Ellipse | Pink | Identified employees |
| Port | Dot | Cyan | Open ports/services |
| Directory | Box | Teal | Discovered directories |

## Project Structure

```
redsurface/
├── main.py                 # CLI entry point
├── core/
│   ├── config.py           # Scan configuration & modes
│   ├── target.py           # Target state management
│   ├── wizard.py           # Interactive CLI wizard
│   ├── graph.py            # Graph data structures
│   └── graph_engine.py     # NetworkX + PyVis builder
├── modules/
│   ├── discovery.py        # Subdomain & DNS resolution
│   ├── fingerprint.py      # Technology & WAF detection
│   ├── osint.py            # Email & people discovery
│   ├── active_recon.py     # Directory enum & zone transfer
│   ├── port_intel.py       # Shodan port intelligence
│   └── phishing.py         # Phishing simulation
├── utils/
│   ├── logger.py           # Colored logging
│   ├── output.py           # File output helpers
│   └── report_generator.py # HTML report generation
└── lib/                    # Frontend assets (vis.js, tom-select)
```

## API Keys

| Service | Purpose | Get Key |
|---------|---------|---------|
| Shodan | Port/service intelligence | [shodan.io](https://shodan.io) |
| Hunter.io | Email discovery | [hunter.io](https://hunter.io) |
| NVD | CVE vulnerability data | [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key) |
| GitHub | Code/commit OSINT | [github.com/settings/tokens](https://github.com/settings/tokens) |
| HIBP | Breach detection | [haveibeenpwned.com/API](https://haveibeenpwned.com/API/Key) |

## Requirements

- Python 3.9+
- httpx, dnspython, networkx, pyvis, questionary, flask

## Disclaimer

⚠️ **This tool is intended for authorized security testing and research only.**

- Always obtain proper written authorization before scanning any target
- The phishing module is for **authorized red team exercises only**
- Unauthorized use may violate computer crime laws
- The authors are not responsible for misuse of this tool

## License

MIT
