# RedSurface

**Attack Surface Intelligence Graph Generator**

A modular Python CLI tool for external reconnaissance that discovers assets, fingerprints technologies, and generates an interactive Attack Surface Graph.

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

## Features

- **Infrastructure Discovery** - Subdomain enumeration & async DNS resolution
- **Cloud Detection** - Identifies AWS, Azure, GCP, Cloudflare hosted assets
- **Technology Fingerprinting** - Detects web technologies from HTTP headers
- **Vulnerability Mapping** - Maps technologies to known CVEs
- **OSINT Collection** - Emails & employee discovery (PGP, GitHub, Hunter.io, crt.sh)
- **Interactive Graph** - Generates HTML visualization with PyVis

## Installation

```bash
git clone https://github.com/yourusername/redsurface.git
cd redsurface
pip install -r requirements.txt
```

## Quick Start

```bash
# Basic scan
python main.py --target example.com

# With OSINT and verbose output
python main.py --target example.com --verbose

# With API keys for enhanced OSINT
python main.py --target example.com --hunter-key YOUR_KEY --github-token YOUR_TOKEN

# Skip OSINT phase
python main.py --target example.com --skip-osint
```

## Output

Results are saved to `./output/`:
- `domain_results.json` - Raw scan data
- `domain_graph.json` - Graph structure
- `domain_graph.html` - Interactive visualization

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

## Project Structure

```
redsurface/
├── main.py              # CLI entry point
├── core/
│   ├── target.py        # Target state management
│   └── graph_engine.py  # NetworkX + PyVis graph builder
├── modules/
│   ├── discovery.py     # Subdomain & DNS resolution
│   ├── fingerprint.py   # Technology detection
│   └── osint.py         # Email & people discovery
└── utils/
    ├── logger.py        # Colored logging
    └── output.py        # File output helpers
```

## Requirements

- Python 3.9+
- httpx, dnspython, networkx, pyvis

## Disclaimer

This tool is intended for authorized security testing and research only. Always obtain proper authorization before scanning any target.

## License

MIT
