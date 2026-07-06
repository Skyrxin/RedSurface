#!/usr/bin/env python3
"""
Refresh the vendored WhatsMyName dataset used by the SocialEnumerator engine.

WhatsMyName (https://github.com/WebBreacher/WhatsMyName) is a community-maintained
catalogue of sites and their username-existence detection rules. We vendor a copy
in data/wmn-data.json so scans work offline and don't depend on GitHub at runtime.

Usage:
    python scripts/update_wmn.py
"""
import json
import sys
from pathlib import Path

import httpx

WMN_URL = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
DEST = Path(__file__).resolve().parent.parent / "data" / "wmn-data.json"


def main() -> int:
    print(f"Fetching {WMN_URL} ...")
    try:
        resp = httpx.get(WMN_URL, timeout=30, follow_redirects=True)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"[!] Failed to fetch dataset: {e}")
        return 1

    sites = data.get("sites", [])
    if not sites:
        print("[!] Dataset had no 'sites' — aborting so we don't clobber the vendored copy.")
        return 1

    DEST.parent.mkdir(parents=True, exist_ok=True)
    with open(DEST, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)

    print(f"[+] Wrote {DEST} ({len(sites)} sites)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
